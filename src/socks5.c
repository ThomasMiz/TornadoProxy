#include <errno.h>
#include <limits.h>
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

#include "request.h"
#include "socks5.h"

unsigned socksv5_handle_read(TSelectorKey* key) {
    TClientData* clientData = key->data;

    // Receive the bytes into the client's buffer.
    ssize_t received = recv(key->fd, clientData->buffer + clientData->bufferLength, CLIENT_RECV_BUFFER_SIZE - clientData->bufferLength, 0);
    if (received <= 0) {
        printf("recv() returned %ld, closing client %d\n", received, key->fd);
        selector_unregister_fd(key->s, key->fd);
        return DONE;
    }

    clientData->bufferLength += received;
    printf("recv() %ld bytes from client %d [total in buffer %u]\n", received, key->fd, clientData->bufferLength);

    // We want to wait until this fd is available for writing. If there is more space in the buffer, the for reading too.
    TFdInterests newInterests = OP_WRITE;
    if (clientData->bufferLength < CLIENT_RECV_BUFFER_SIZE)
        newInterests |= OP_READ;

    // Update the interests in the selector.
    selector_set_interest_key(key, newInterests);
    return COPY;
}

unsigned socksv5_handle_write(TSelectorKey* key) {
    TClientData* clientData = key->data;

    // Try to send as many of the bytes as we have in the buffer.
    ssize_t sent = send(key->fd, clientData->buffer, clientData->bufferLength, 0);
    if (sent <= 0) {
        printf("send() returned %ld, closing client %d\n", sent, key->fd);
        selector_unregister_fd(key->s, key->fd);
        return DONE;
    }

    // TODO: Circular buffer or something idk
    // Why not a torus-shaped buffer? 🤔
    clientData->bufferLength -= sent;
    if (clientData->bufferLength > 0)
        memmove(clientData->buffer, clientData->buffer + sent, clientData->bufferLength);

    printf("send() %ld bytes to client %d [%u remaining]\n", sent, key->fd, clientData->bufferLength);

    // Calculate the new interests for this socket. We want to read, and possibly write if we still have more buffer data.
    TFdInterests newInterests = OP_READ;
    if (clientData->bufferLength > 0)
        newInterests |= OP_WRITE;

    // Update the interests in the selector.
    selector_set_interest_key(key, newInterests);
    return COPY;
}

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
    // {
    //     .state = REQUEST_CONNECTING,
    //     .on_arrival = request_connecting_init,
    //     .on_write_ready = request_connecting,
    // },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = requestWrite,
    },
    {
        .state = COPY,
        .on_read_ready = socksv5_handle_read,
        .on_write_ready = socksv5_handle_write,
    },
    {
        .state = DONE,
    },
    {
        .state = ERROR,
    }};

void socksv5_close(TSelectorKey* key) {
    TClientData* clientData = key->data;

    // Free the memory associated with this client.
    free(clientData->buffer);
    free(clientData);

    // Close the socket file descriptor associated with this client.
    close(key->fd);

    printf("Client closed: %d\n", key->fd);
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

static void socksv5_block(TSelectorKey *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
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
    if (clientData == NULL || (clientData->buffer = malloc(CLIENT_RECV_BUFFER_SIZE)) == NULL) {
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

    clientData->stm.initial = NEGOTIATION_READ; // TODO CAMBIAR LUEGO
    clientData->stm.max_state = ERROR;
    clientData->stm.states = client_statb1;

    stm_init(&clientData->stm);

    TSelectorStatus status = selector_register(key->s, newClientSocket, handler, OP_READ, clientData);
    if (status != SELECTOR_SUCCESS) {
        printf("Failed to register new client into selector: %s\n", selector_error(status));
        free(clientData->buffer);
        free(clientData);
        return;
    }

    printf("New client registered successfully!\n");
}