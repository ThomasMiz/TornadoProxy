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

#include "selector.h"
#include "socks5.h"

#define CLIENT_RECV_BUFFER_SIZE 4096

typedef struct {
    fd_handler handler;
    char* buffer;
    unsigned int bufferLength;
} socksv5_client_data;

void socksv5_passive_accept(struct selector_key* key) {
    printf("New client received\n");
    struct sockaddr_storage clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);
    int newClientSocket = accept(key->fd, (struct sockaddr*)&clientAddress, &clientAddressLen);
    printf("New client accepted at socket fd %d\n", newClientSocket);

    socksv5_client_data* clientData = calloc(1, sizeof(socksv5_client_data));
    if (clientData == NULL || (clientData->buffer = malloc(CLIENT_RECV_BUFFER_SIZE)) == NULL) {
        free(clientData);
        printf("Failed to alloc clientData for new client! Did we run out of memory?\n");
        close(newClientSocket);
        return;
    }

    fd_handler* handler = &clientData->handler;
    handler->handle_read = socksv5_handle_read;
    handler->handle_write = socksv5_handle_write;
    handler->handle_close = socksv5_handle_close;
    
    selector_status status = selector_register(key->s, newClientSocket, handler, OP_READ, clientData);
    if (status != SELECTOR_SUCCESS) {
        printf("Failed to register new client into selector: %s\n", selector_error(status));
        free(clientData->buffer);
        free(clientData);
        return;
    }

    printf("New client registered successfully!\n");
}

void socksv5_handle_read(struct selector_key* key) {
    socksv5_client_data* clientData = key->data;

    // Receive the bytes into the client's buffer.
    ssize_t received = recv(key->fd, clientData->buffer + clientData->bufferLength, CLIENT_RECV_BUFFER_SIZE - clientData->bufferLength, 0);
    if (received <= 0) { 
        printf("recv() returned %ld, closing client %d\n", received, key->fd);
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    clientData->bufferLength += received;
    printf("recv() %ld bytes from client %d [total in buffer %u]\n", received, key->fd, clientData->bufferLength);

    // We want to wait until this fd is available for writing. If there is more space in the buffer, the for reading too.
    fd_interest newInterests = OP_WRITE;
    if (clientData->bufferLength < CLIENT_RECV_BUFFER_SIZE)
        newInterests |= OP_READ;
    
    // Update the interests in the selector.
    selector_set_interest_key(key, newInterests);
}

void socksv5_handle_write(struct selector_key* key) {
    socksv5_client_data* clientData = key->data;

    // Try to send as many of the bytes as we have in the buffer.
    ssize_t sent = send(key->fd, clientData->buffer, clientData->bufferLength, 0);
    if (sent <= 0) { 
        printf("send() returned %ld, closing client %d\n", sent, key->fd);
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    // TODO: Circular buffer or something idk
    // Why not a torus-shaped buffer? 🤔
    clientData->bufferLength -= sent;
    if (clientData->bufferLength > 0)
        memmove(clientData->buffer, clientData->buffer + sent, clientData->bufferLength);

    printf("send() %ld bytes to client %d [%u remaining]\n", sent, key->fd, clientData->bufferLength);
    
    // Calculate the new interests for this socket. We want to read, and possibly write if we still have more buffer data.
    fd_interest newInterests = OP_READ;
    if (clientData->bufferLength > 0)
        newInterests |= OP_WRITE;
    
    // Update the interests in the selector.
    selector_set_interest_key(key, newInterests);
}

void socksv5_handle_close(struct selector_key* key) {
    socksv5_client_data* clientData = key->data;

    // Free the memory associated with this client.
    free(clientData->buffer);
    free(clientData);

    // Close the socket file descriptor associated with this client.
    close(key->fd);

    printf("Client closed: %d\n", key->fd);
}