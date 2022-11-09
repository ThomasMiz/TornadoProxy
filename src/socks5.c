#include "socks5.h"
#include "assert.h"
#include "copy.h"
#include "netutils.h"
#include "request.h"
#include "request_connecting.h"
#include "selector.h"
#include "stm.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static const struct state_definition client_statb1[] = {
    {
        .state = NEGOTIATION_READ,
        .on_arrival = negotiationReadInit,
        .on_read_ready = negotiationRead,
    },
    {
        .state = NEGOTIATION_WRITE,
        .on_write_ready = negotiationWrite,
    },
    {
        .state = REQUEST_READ,
        .on_arrival = requestReadInit,
        //.on_departure = requestReadClose,
        .on_read_ready = requestRead,
    },
    {
        .state = REQUEST_RESOLV,
        .on_block_ready = requestResolveDone,
    },
    {
        .state = REQUEST_CONNECTING,
        .on_arrival = request_connecting_init,
        .on_write_ready = request_connecting,
    },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = requestWrite,
    },
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

static void socksv5_read(TSelectorKey* key);
static void socksv5_write(TSelectorKey* key);
static void socksv5_close(TSelectorKey* key);
static void socksv5_block(TSelectorKey* key);
static TFdHandler handler = {
    .handle_read = socksv5_read,
    .handle_write = socksv5_write,
    .handle_close = socksv5_close,
    .handle_block = socksv5_block,
};

TFdHandler* get_state_handler() {
    return &handler;
}

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

    // Consider using a function to initialize the TClientData structure.
    TClientData* clientData = calloc(1, sizeof(TClientData));
    if (clientData == NULL) {
        free(clientData);
        printf("Failed to alloc clientData for new client! Did we run out of memory?\n");
        close(newClientSocket);
        return;
    }

    TFdHandler* handler = &clientData->handler;
    handler->handle_read = socksv5_read;
    handler->handle_write = socksv5_write;
    handler->handle_close = socksv5_close;
    handler->handle_block = socksv5_block;

    clientData->stm.initial = NEGOTIATION_READ;
    clientData->stm.max_state = ERROR;
    clientData->stm.states = client_statb1;
    clientData->client_fd = newClientSocket;

    buffer_init(&clientData->origin_buffer, N(clientData->origin_buffer_array), clientData->origin_buffer_array);
    buffer_init(&clientData->client_buffer, N(clientData->client_buffer_array), clientData->client_buffer_array);

    /*struct sockaddr_in* sockaddr = malloc(sizeof(struct sockaddr_in));

    clientData->origin_resolution = malloc(sizeof(struct addrinfo));

    // HARDCODEAR OS
    *sockaddr = (struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_port = htons(5000),
    };
    inet_aton("0.0.0.0", &(sockaddr->sin_addr));
    *(clientData->origin_resolution) = (struct addrinfo){
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_addr = (struct sockaddr*)sockaddr,
        .ai_addrlen = sizeof(*sockaddr),
    };
    char buf[BUFFER_SIZE] = {0};
    sockaddr_to_human(buf, BUFFER_SIZE, clientData->origin_resolution->ai_addr);

    printf("Hardcoding origin to %s\n", buf);*/

    stm_init(&clientData->stm);

    TSelectorStatus status = selector_register(key->s, newClientSocket, handler, OP_READ, clientData);

    if (status != SELECTOR_SUCCESS) {
        printf("Failed to register new client into selector: %s\n", selector_error(status));
        free(clientData);
        return;
    }
    printf("New client registered successfully!\n");
}
