// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "args.h"
#include "logging/logger.h"
#include "logging/util.h"
#include "mgmt/mgmt.h"
#include "logging/metrics.h"
#include "negotiation/negotiationParser.h"
#include "selector.h"
#include "socks5.h"
#include "users.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static bool terminationRequested = false;

static void sigterm_handler(const int signal) {
    logf(LOG_INFO, "Signal %d, cleaning up and exiting", signal);
    terminationRequested = true;
}

static int setupSockAddr(char* addr, unsigned short port, void* res, socklen_t* socklenResult) {
    int ipv6 = strchr(addr, ':') != NULL;

    if (ipv6) {
        // Parse addr as IPv6
        struct sockaddr_in6 sock6;
        memset(&sock6, 0, sizeof(sock6));

        sock6.sin6_family = AF_INET6;
        sock6.sin6_addr = in6addr_any;
        sock6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, addr, &sock6.sin6_addr) != 1) {
            log(LOG_ERROR, "Failed IP conversion for IPv6");
            return 1;
        }

        *((struct sockaddr_in6*)res) = sock6;
        *socklenResult = sizeof(struct sockaddr_in6);
        return 0;
    }

    // Parse addr as IPv4
    struct sockaddr_in sock4;
    memset(&sock4, 0, sizeof(sock4));
    sock4.sin_family = AF_INET;
    sock4.sin_addr.s_addr = INADDR_ANY;
    sock4.sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &sock4.sin_addr) != 1) {
        log(LOG_ERROR, "Failed IP conversion for IPv4");
        return 1;
    }

    *((struct sockaddr_in*)res) = sock4;
    *socklenResult = sizeof(struct sockaddr_in);
    return 0;
}

int main(const int argc, char** argv) {

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // no tenemos nada que leer de stdin
    close(STDIN_FILENO);

    // Creamos el selector
    const char* err_msg = NULL;
    TSelectorStatus ss = SELECTOR_SUCCESS;
    TSelector selector = NULL;
    const TSelectorInit conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0,
        },
    };
    if (0 != selector_init(&conf)) {
        // NOTE: Can't do logging without a selector
        fprintf(stderr, "Failed to initialize selector. Server closing.");
        exit(1);
    }

    selector = selector_new(1024);
    if (selector == NULL) {
        fprintf(stderr, "Failed to create selector. Server closing.");
        selector_close();
        exit(1);
    }

    metricsInit();
    loggerInit(selector, "", stdout);
    loggerSetLevel(LOG_OUTPUT);
    usersInit(NULL);
    changeAuthMethod(NEG_METHOD_PASS); // Initially, authentication with user&pass is required.

    struct socks5args args;
    parse_args(argc, argv, &args);

    for (int i = 0; i < args.nusers; ++i) {
        usersCreate(args.users[i].name, args.users[i].pass, 0, UPRIV_USER, 0);
    }

    if(!args.disectorsEnabled){
        turnOffPDissector();
    }

    // Listening on just IPv6 allow us to handle both IPv6 and IPv4 connections!
    // https://stackoverflow.com/questions/50208540/cant-listen-on-ipv4-and-ipv6-together-address-already-in-use

    struct sockaddr_storage auxAddr;
    memset(&auxAddr, 0, sizeof(auxAddr));
    socklen_t auxAddrLen = sizeof(auxAddr);
    int server = -1;
    int mgmtServer = -1;

    if (setupSockAddr(args.socksAddr, args.socksPort, &auxAddr, &auxAddrLen)) {
        err_msg = "Invalid socks5 source address";
        errno = -1;
        goto finally;
    }

    server = socket(auxAddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (server < 0) {
        err_msg = "Unable to create socket";
        errno = -1;
        goto finally;
    }

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if (bind(server, (struct sockaddr*)&auxAddr, auxAddrLen) < 0) {
        err_msg = "Unable to bind socket";
        goto finally;
    }

    if (listen(server, 20) < 0) {
        err_msg = "Unable to listen";
        goto finally;
    }

    if (selector_fd_set_nio(server) == -1) {
        err_msg = "Getting server socket flags";
        goto finally;
    }

    memset(&auxAddr, 0, sizeof(auxAddr));
    auxAddrLen = sizeof(auxAddr);
    if (getsockname(server, (struct sockaddr*)&auxAddr, &auxAddrLen) >= 0) {
        logf(LOG_OUTPUT, "Listening for socks5 connections on TCP address %s", printSocketAddress((struct sockaddr*)&auxAddr));
    } else {
        logf(LOG_OUTPUT, "Listening for socks5 connections on TCP port %d", args.socksPort);
    }

    // MANAGEMENT
    memset(&auxAddr, 0, sizeof(auxAddr));
    auxAddrLen = sizeof(auxAddr);
    if (setupSockAddr(args.mngAddr, args.mngPort, &auxAddr, &auxAddrLen)) {
        err_msg = "Invalid management source address";
        goto finally;
    }

    mgmtServer = socket(auxAddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (mgmtServer < 0) {
        err_msg = "Unable to create socket";
        goto finally;
    }

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(mgmtServer, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if (bind(mgmtServer, (struct sockaddr*)&auxAddr, auxAddrLen) < 0) {
        err_msg = "Unable to bind socket";
        goto finally;
    }

    if (listen(mgmtServer, 20) < 0) {
        err_msg = "Unable to listen";
        goto finally;
    }

    if (selector_fd_set_nio(mgmtServer) == -1) {
        err_msg = "Getting server socket flags";
        goto finally;
    }

    memset(&auxAddr, 0, sizeof(auxAddr));
    auxAddrLen = sizeof(auxAddr);
    if (getsockname(mgmtServer, (struct sockaddr*)&auxAddr, &auxAddrLen) >= 0) {
        logf(LOG_OUTPUT, "Listening for management connections on TCP address %s", printSocketAddress((struct sockaddr*)&auxAddr));
    } else {
        logf(LOG_OUTPUT, "Listening for management connections on TCP port %d", args.mngPort);
    }

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    const TFdHandler socksv5 = {
        .handle_read = socksv5PassivAccept,
        .handle_write = NULL,
        .handle_close = NULL, // nada que liberar
    };

    const TFdHandler management = {
        .handle_read = mgmtPassiveAccept,
        .handle_write = NULL,
        .handle_close = NULL, // nada que liberar
    };

    ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "Registering fd";
        goto finally;
    }

    ss = selector_register(selector, mgmtServer, &management, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "Registering fd";
        goto finally;
    }
    while (!terminationRequested) {
        err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "Serving";
            goto finally;
        }
    }
    if (err_msg == NULL) {
        err_msg = "Closing";
    }

    int ret = 0;
finally:
    usersFinalize();
    loggerFinalize();
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "Unknown error" : err_msg, ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
        ret = 2;
    } else if (errno < 0) {
        fprintf(stderr, "%s\n", (err_msg == NULL) ? "Unknown error" : err_msg);
    } else {
        perror(err_msg);
        ret = 1;
    }
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    if (server >= 0) {
        close(server);
    }
    if (mgmtServer >= 0) {
        close(server);
    }
    return ret;
}
