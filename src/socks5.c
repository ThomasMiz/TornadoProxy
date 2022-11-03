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

#include "socks5.h"
#include "stm.h"

#define CLIENT_RECV_BUFFER_SIZE 4096

typedef struct {
    TFdHandler handler;
    char* buffer;
    unsigned int bufferLength;
    struct state_machine stm;
} TClientData;

// obtiene el struct socks5* desde la key
#define ATTACHMENT(key) ( (TClientData *)(key)->data )

enum socks_state {
    /*
        recibe el mensaje `hello` del cliente y lo procesa

    Intereses: 
        - OP_READ sobre client_fd

    Transiciones: 
        - HELLO_READ mientras el mensaje no esta completo
        - HELLO_WRITE cuando esta completo
        - ERROR ante cualquier error (IO/parseo)
    */
//    HELLO_READ,

    /*
        envia la respuesta del `hello` al cliente

    Intereses: 
        - OP_WRITE sobre client_fd

    Transiciones: 
        - HELLO_WRITE mientras queden bytes por enviar
        - REQUEST_READ cuando se enviaron todos los bytes
        - ERROR ante cualquier error (IO/parseo)
    */
//    HELLO_WRITE,

    /*
        recibe el mensaje `request` del cliente e inicia su proceso

    Intereses: 
        - OP_READ sobre client_fd

    Transiciones: 
        - REQUEST_READ mientras el mensaje no este completo
        - REQUEST_RESOLV si quiere resolver un nombre DNS
        - REQUEST_CONNECTING si no requiere resolver DNS y podemos inicial la conexion con el OS
        - REQUEST_WRITE si determinamos que el mensaje no lo podemos procesar (ej. no se soporta un comando)
        - ERROR ante cualquier error (IO/parseo)
    */
//    REQUEST_READ,

    /*
        Espera la resolucion DNS

    Intereses: 
        - OP_NOOP sobre client_fd. Espera un evento de que la tarea bloqueante terminó

    Transiciones: 
        - REQUEST_CONNECTING si se logra la resolucion y se puede iniciar la conexion al OS.
        - REQUEST_WRITE en otro caso
    */
//    REQUEST_RESOLV,

    /*
        Espera que se establezca la conesion al OS

    Intereses: 
        - OP_WRITE sobre client_fd

    Transiciones: 
        - REQUEST_CWRITE cuando se haya logrado o no establecer la conexion
    */
//    REQUEST_CONNECTING,

    /*
        Envia la respuesta del `request` al cliente

    Intereses: 
        - OP_WRITE sobre client_fd
        - OP_NOOP sobre origin_fd

    Transiciones: 
        - HELLO_WRITE mientras queden bytes por enviar
        - COPY si el request fue exitoso y teemos que copiar el contenido de los descriptores
        - ERRO ante I/O error
    */
//    REQUEST_WRITE,

    /*
        Copia bytes entre client_fd y origin_fd

    Intereses: 
        - OP_READ si hay espacio para escribir en el buffer de lectura
        - OP_WRITE si hay bytes para leer en el buffer de escritura

    Transiciones: 
        - DONE cuando no queda nada mas por copiar
    */
   COPY,

    // estados terminales
    DONE,
    ERROR,

};

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
    // {
    //     .state = REQUEST_CONNECTING,
    //     .on_arrival = request_connecting_init,
    //     .on_write_ready = request_connecting,
    // },
    // {
    //     .state = REQUEST_WRITE,
    //     .on_write_ready = request_write,
    // },
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
    }
};

void socksv5_close(TSelectorKey* key) {
    TClientData* clientData = key->data;

    // Free the memory associated with this client.
    free(clientData->buffer);
    free(clientData);

    // Close the socket file descriptor associated with this client.
    close(key->fd);

    printf("Client closed: %d\n", key->fd);
}

static void socksv5_read(TSelectorKey *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_state st = stm_handler_read(stm, key);
    // ERROR HANDLING
}

static void socksv5_write(TSelectorKey *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_state st = stm_handler_write(stm, key);
    // ERROR HANDLING
}


void socksv5_passive_accept(TSelectorKey* key) {
    printf("New client received\n");
    struct sockaddr_storage clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);
    int newClientSocket = accept(key->fd, (struct sockaddr*)&clientAddress, &clientAddressLen);
    printf("New client accepted at socket fd %d\n", newClientSocket);

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

    clientData->stm.initial = COPY; // TODO CAMBIAR LUEGO
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