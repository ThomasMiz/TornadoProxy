#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "socks5.h"
#include "stm.h"
#include "netutils.h"
#include "selector.h"
#include "assert.h"
#include "request_connecting.h"
#include "copy.h"


static void socksv5_read(TSelectorKey* key);
static void socksv5_write(TSelectorKey* key);
static void socksv5_close(TSelectorKey* key);
static void socksv5_block(TSelectorKey* key);
static const TFdHandler handler = {
    .handle_read = socksv5_read,
    .handle_write = socksv5_write,
    .handle_close = socksv5_close,
    .handle_block = socksv5_block,
};

TFdHandler * get_state_handler() {
    return &handler;
}

static const struct state_definition client_statb1[] = {
    // {
    //     .state = HELLO_READ,
    //     .on_arrival = hello_read_init,
    //     .on_departure = hello_read_close,
    //     .on_read_ready = hello_read,
    // },
    // {
    //     .state = HELLO_WRITE,
    //     .on_write_ready = hello_write,
    // },
    // {
    //     .state = REQUEST_READ,
    //     .on_arrival = request_read_init,
    //     .on_departure = request_read_close,
    //     .on_read_ready = request_read,
    // },
    // {
    //     .state = REQUEST_RESOLV,
    //     .on_block_ready = request_resolv_done,
    // },
    {
        .state = REQUEST_CONNECTING,
        .on_arrival = request_connecting_init,
        .on_write_ready = request_connecting,
    },
    // {
    //     .state = REQUEST_WRITE,
    //     .on_write_ready = request_write,
    // },
    {
        .state = COPY,
        .on_read_ready = socksv5_handle_read,
        .on_write_ready = socksv5_handle_write,
        .on_departure = socksv5_handle_close,

    },
    {
        .state = DONE,
    },
    {
        .state = ERROR,
    }};

void socksv5_close(TSelectorKey* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    stm_handler_close(stm, key);
    // ERROR HANDLING
}

static void socksv5_read(TSelectorKey* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum socks_state st = stm_handler_read(stm, key);
    // ERROR HANDLING
}

static void socksv5_write(TSelectorKey* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum socks_state st = stm_handler_write(stm, key);
    // ERROR HANDLING
}

static void socksv5_block(TSelectorKey* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum socks_state st = stm_handler_block(stm, key);
    // ERROR HANDLING
}

void socksv5_passive_accept(TSelectorKey* key) {
    printf("New client received\n");
    struct sockaddr_storage clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);
    int newClientSocket = accept(key->fd, (struct sockaddr*)&clientAddress, &clientAddressLen);
    printf("New client accepted at socket fd %d\n", newClientSocket);

    TClientData* clientData = calloc(1, sizeof(TClientData));
    if (clientData == NULL) {
        free(clientData);
        printf("Failed to alloc clientData for new client! Did we run out of memory?\n");
        close(newClientSocket);
        return;
    }

    clientData->stm.initial = REQUEST_CONNECTING; // TODO CAMBIAR LUEGO
    clientData->stm.max_state = ERROR;
    clientData->stm.states = client_statb1;
    clientData->client_fd = newClientSocket;

    buffer_init(&clientData->origin_buffer, N(clientData->origin_buffer_array), clientData->origin_buffer_array);

    buffer_init(&clientData->client_buffer, N(clientData->client_buffer_array), clientData->client_buffer_array);
    struct sockaddr_in* sockaddr = malloc(sizeof(struct sockaddr_in));
    clientData->origin_resolution = malloc(sizeof(struct addrinfo));

    // HARDCODEAR OS
    *sockaddr = (struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_port = htons(5000),
    };
    inet_aton("0.0.0.0", &(sockaddr->sin_addr));
    *(clientData->origin_resolution) = (struct addrinfo) {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_addr = (struct sockaddr*)sockaddr,
        .ai_addrlen = sizeof(*sockaddr),
    };
    char buf[BUFFER_SIZE] = {0};
    sockaddr_to_human(buf, BUFFER_SIZE, clientData->origin_resolution->ai_addr);

    printf("Hardcoding origin to %s\n", buf);

    stm_init(&clientData->stm);

    TSelectorStatus status = selector_register(key->s, newClientSocket, &handler, OP_WRITE, clientData);
    if (status != SELECTOR_SUCCESS) {
        printf("Failed to register new client into selector: %s\n", selector_error(status));
        free(clientData);
        return;
    }

    printf("New client registered successfully!\n");
}