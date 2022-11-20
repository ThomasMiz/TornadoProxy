// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "selector.h"
#include "socks5.h"
#include "args.h"
#include "users.h"
#include "logging/logger.h"
#include "mgmt/mgmt.h"

static bool terminationRequested = false;


static void sigterm_handler(const int signal) {
    logf("Signal %s, cleaning up and exiting", strerror(signal));
    terminationRequested = true;
}

static uint8_t setupSockAddr(char * addr, unsigned short port, void * res) {
    int ipv6 = strchr(addr, ':') != NULL; 
    struct sockaddr_in sock4;
	struct sockaddr_in6 sock6;
    
    if(ipv6) {
		memset(&sock6, 0, sizeof(sock4));
        
		sock6.sin6_family = AF_INET6;
		sock6.sin6_addr = in6addr_any;
		sock6.sin6_port = htons(port);
		if(inet_pton(AF_INET6, addr, &sock6.sin6_addr) != 1) {
			//log(LOG_ERROR, "failed IP conversion for %s", "IPv6"); // TODO: Remove
            logf("failed IP conversion for %s", "IPv6");
			return -1;
		}
        *((struct sockaddr_in6 * )res) = sock6;
        return sizeof(struct sockaddr_in6);
	} else {
		memset(&sock4, 0, sizeof(sock4));
		sock4.sin_family =AF_INET;
		sock4.sin_addr.s_addr = INADDR_ANY;
		sock4.sin_port = htons(port);
		if(inet_pton(AF_INET, addr, &sock4.sin_addr) != 1) {
			//log(LOG_ERROR, "failed IP conversion for %s", "IPv4"); // TODO: Remove
			logf("failed IP conversion for %s", "IPv4");
			return -1;
		}
        *((struct sockaddr_in * )res) = sock4;
        return sizeof(struct sockaddr_in);
	}
}

int main(const int argc, char** argv) {

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // no tenemos nada que leer de stdin
    close(STDIN_FILENO);

    // Creamos el selector
    const char *err_msg = NULL;
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
        // err_msg = "initializing selector";
        // goto finally;
    }

    selector = selector_new(1024);
    if (selector == NULL) {
        fprintf(stderr, "Failed to create selector. Server closing.");
        exit(1);
        //err_msg = "unable to create selector";
        //goto finally;
    }

    loggerInit(selector, "", stdout);
    usersInit(NULL);

    struct socks5args args;
    parse_args(argc, argv, &args);

    // unsigned port = args.socksPort;

    for(int i=0 ; i<args.nusers ; ++i){
        usersCreate(args.users[i].name, args.users[i].pass, 0, UPRIV_USER, 0);
    }

    // Listening on just IPv6 allow us to handle both IPv6 and IPv4 connections!
    // https://stackoverflow.com/questions/50208540/cant-listen-on-ipv4-and-ipv6-together-address-already-in-use

   
    // log(DEBUG, "hola %d %d", sizeof(struct sockaddr_in), sizeof(struct sockaddr_in6)); // TODO: Remove
    struct sockaddr_in6 aux;
    memset(&aux, 0, sizeof(aux));
    void * p = (void *)&aux;
    uint8_t size = setupSockAddr(args.socksAddr, args.socksPort,p);
    // log(DEBUG, "hola %s", "a"); // TODO: Remove
    int ipv6 = strchr(args.socksAddr, ':') != NULL; 
    const int server = socket(ipv6? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server < 0) {
        err_msg = "unable to create socket";
        goto finally;
    }

    //fprintf(stdout, "Listening on TCP port %d\n", args.socksPort); // TODO: Remove
    logf("Listening on TCP port %d", args.socksPort);

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));

    
    if (bind(server, (struct sockaddr *) p, size) < 0) {
        err_msg = "unable to bind socket";
        goto finally;
    }

    if (listen(server, 20) < 0) {
        err_msg = "unable to listen";
        goto finally;
    }

        if (selector_fd_set_nio(server) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }


    // MANAGEMENT
    memset(&aux, 0, sizeof(aux));
    size = setupSockAddr(args.mngAddr, args.mngPort, p);
    
    ipv6 = strchr(args.mngAddr, ':') != NULL; 
    const int mgmtServer = socket(ipv6? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (mgmtServer < 0) {
        err_msg = "unable to create socket";
        goto finally;
    }

    //fprintf(stdout, "Listening on TCP port %d (socks5) and %d (management)\n", args.socksPort, args.mngPort); // TODO: Remove
    logf("Listening on TCP port %d (socks5) and %d (management)", args.socksPort, args.mngPort);

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(mgmtServer, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));

    
    if (bind(mgmtServer,  (struct sockaddr *) p, size) < 0) {
        err_msg = "unable to bind socket";
        goto finally;
    }

    if (listen(mgmtServer, 20) < 0) {
        err_msg = "unable to listen";
        goto finally;
    }

    if (selector_fd_set_nio(mgmtServer) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
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
        err_msg = "registering fd";
        goto finally;
    }

    ss = selector_register(selector, mgmtServer, &management, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }
    while (!terminationRequested) {
        err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    if (err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;
    finally:
    usersFinalize();
    loggerFinalize();
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
                ss == SELECTOR_IO
                ? strerror(errno)
                : selector_error(ss));
        ret = 2;
    } else if (err_msg) {
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
    return ret;
}