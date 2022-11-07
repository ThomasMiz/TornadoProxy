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

#define BUFFER_SIZE 4096
#define N(x) (sizeof(x) / sizeof((x)[0]))

typedef struct {
    TFdHandler handler;
    uint8_t client_buffer_array[1024];
    uint8_t origin_buffer_array[1024];
    buffer client_buffer;
    buffer origin_buffer;
    unsigned int bufferLength;
    struct state_machine stm;

    struct addrinfo* origin_resolution;

    int client_fd;

    // informacion del OS
    int origin_fd;
} TClientData;

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

#define ATTACHMENT(key) ((TClientData*)(key)->data)

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
    REQUEST_CONNECTING,

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

void request_connecting_init(const unsigned state, TSelectorKey* key) {
    TClientData* d = ATTACHMENT(key);
    TFdInterests curr_interests;
    selector_get_interests(key, &curr_interests);
    selector_set_interest(key->s, d->client_fd, OP_WRITE | curr_interests);
}

unsigned request_connecting(TSelectorKey* key) {
    TClientData* d = ATTACHMENT(key);
    TFdInterests curr_interests;
    selector_get_interests(key, &curr_interests);
    if (d->client_fd == key->fd) // Se llama primero al handler del cliente, y entonces nos conectamos al OS
    {
        selector_set_interest(key->s, d->client_fd, INTEREST_OFF(curr_interests, OP_WRITE));
        assert(d->origin_resolution != NULL);
        d->origin_fd = socket(d->origin_resolution->ai_family, d->origin_resolution->ai_socktype, d->origin_resolution->ai_protocol);
        if (d->origin_fd >= 0) {
            selector_fd_set_nio(d->origin_fd);
            char address_buf[1024];
            sockaddr_to_human(address_buf, 1024, d->origin_resolution->ai_addr);
            printf("Connecting to %s", address_buf);
            if (connect(d->origin_fd, d->origin_resolution->ai_addr, d->origin_resolution->ai_addrlen) == 0 || errno == EINPROGRESS) {
                if (selector_register(key->s, d->origin_fd, &handler, OP_WRITE, d) != SELECTOR_SUCCESS) { // Registramos al FD del OS con OP_WRITE y la misma state machine, entonces esperamos a que se corra el handler para REQUEST_CONNECTING del lado del OS
                    return ERROR;
                }
                return REQUEST_CONNECTING;
            }
        }
        return ERROR;
    }

    // Ya nos conectamos (handler del lado del OS)

    char buf[BUFFER_SIZE];
    sockaddr_to_human(buf, BUFFER_SIZE, d->origin_resolution->ai_addr);
    printf("Connected to %s\n", buf);
    selector_set_interest(key->s, d->origin_fd, OP_READ | OP_WRITE);
    selector_set_interest(key->s, d->client_fd, OP_READ | OP_WRITE);
    return COPY;
}

unsigned socksv5_handle_read(TSelectorKey* key) {
    TClientData* clientData = key->data;
    buffer* client_buffer = &clientData->client_buffer;
    buffer* origin_buffer = &clientData->origin_buffer;
    int client_fd = clientData->client_fd;
    int origin_fd = clientData->origin_fd;
    char tmp_buf[BUFFER_SIZE];
    size_t capacity;
    TFdInterests curr_interests;
    selector_get_interests(key, &curr_interests);

    if (client_fd == key->fd) {
        // Receive the bytes into the client's buffer.
        if (!buffer_can_write(origin_buffer)) {
            selector_set_interest(key->s, client_fd, OP_READ | curr_interests);
            return COPY;
        }

        u_int8_t* write_ptr = buffer_write_ptr(origin_buffer, &capacity);
        if (capacity > BUFFER_SIZE)
            capacity = BUFFER_SIZE;
        ssize_t read_bytes = read(client_fd, tmp_buf, capacity);
        if (read_bytes > 0) {
            memcpy(write_ptr, tmp_buf, read_bytes);
            buffer_write_adv(origin_buffer, read_bytes);
            size_t remaining;
            buffer_read_ptr(client_buffer, &remaining);
            printf("recv() %ld bytes from client %d [remaining to read %lu]\n", read_bytes, key->fd, remaining);

        } else { // EOF or err
            printf("recv() returned %ld, closing client %d\n", read_bytes, key->fd);
            selector_unregister_fd(key->s, key->fd);
            return DONE;
        }

        // We want to wait until this fd is available for writing. If there is more space in the buffer, the for reading too.
        TFdInterests newInterests = OP_WRITE;
        if (buffer_can_write(origin_buffer))
            newInterests |= OP_READ;

        // Update the interests in the selector.
        selector_set_interest_key(key, newInterests);
    } else { // fd == origin_fd
             // Receive the bytes into the client's buffer.
        if (!buffer_can_write(client_buffer)) {
            selector_set_interest(key->s, origin_fd, OP_READ | curr_interests);
            return COPY;
        }

        uint8_t* write_ptr = buffer_write_ptr(client_buffer, &capacity);
        if (capacity > BUFFER_SIZE)
            capacity = BUFFER_SIZE;
        ssize_t read_bytes = read(origin_fd, tmp_buf, capacity);
        if (read_bytes > 0) {
            memcpy(write_ptr, tmp_buf, read_bytes);
            buffer_write_adv(client_buffer, read_bytes);
            size_t remaining;
            buffer_read_ptr(origin_buffer, &remaining);
            printf("recv() %ld bytes from origin %d [remaining to read %lu]\n", read_bytes, key->fd, remaining);

        } else { // EOF
            printf("recv() returned %ld, closing origin %d\n", read_bytes, key->fd);
            selector_unregister_fd(key->s, key->fd);
            return DONE;
        }

        // We want to wait until this fd is available for writing. If there is more space in the buffer, the for reading too.
        TFdInterests newInterests = OP_WRITE;
        if (buffer_can_write(client_buffer))
            newInterests |= OP_READ;

        // Update the interests in the selector.
        selector_set_interest_key(key, newInterests);
    }
    return COPY;
}

unsigned socksv5_handle_write(TSelectorKey* key) {
    TClientData* clientData = key->data;
    buffer* client_buffer = &clientData->client_buffer;
    buffer* origin_buffer = &clientData->origin_buffer;
    int client_fd = clientData->client_fd;
    int origin_fd = clientData->origin_fd;
    size_t capacity;
    TFdInterests curr_interests;
    selector_get_interests(key, &curr_interests);
    // Try to send as many of the bytes as we have in the buffer.
    if (key->fd == client_fd) {
        if (!buffer_can_read(client_buffer)) {
            selector_set_interest_key(key, OP_WRITE);
            return COPY;
        }
        uint8_t* read_ptr = buffer_read_ptr(client_buffer, &capacity);
        ssize_t sent = send(client_fd, read_ptr, capacity, 0); // habia que usar algun flag?
        if (sent <= 0) {
            printf("send() returned %ld, closing client %d\n", sent, key->fd);
            selector_unregister_fd(key->s, key->fd);
            return DONE;
        }
        buffer_read_adv(client_buffer, sent);

        printf("send() %ld bytes to client %d [%lu remaining]\n", sent, key->fd, capacity - sent);

        // Calculate the new interests for this socket. We want to read, and possibly write if we still have more buffer data.
        TFdInterests newInterests = OP_READ;
        if (buffer_can_read(client_buffer))
            newInterests |= OP_WRITE;

        // Update the interests in the selector.
        selector_set_interest_key(key, newInterests);
    } else {

        if (!buffer_can_read(origin_buffer)) {
            selector_set_interest_key(key, OP_WRITE);
            return COPY;
        }
        uint8_t* read_ptr = buffer_read_ptr(origin_buffer, &capacity);
        ssize_t sent = send(origin_fd, read_ptr, capacity, 0);
        if (sent <= 0) {
            printf("send() returned %ld, closing origin %d\n", sent, key->fd);
            selector_unregister_fd(key->s, key->fd);
            return DONE;
        }
        buffer_read_adv(origin_buffer, sent);

        printf("send() %ld bytes to origin %d [%lu remaining]\n", sent, key->fd, capacity - sent);

        // Calculate the new interests for this socket. We want to read, and possibly write if we still have more buffer data.
        TFdInterests newInterests = OP_READ;
        if (buffer_can_read(origin_buffer))
            newInterests |= OP_WRITE;

        // Update the interests in the selector.
        selector_set_interest_key(key, newInterests);
    }

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

void socksv5_handle_close(const unsigned int state, TSelectorKey* key) {
    TClientData* clientData = key->data;

    // Free the memory associated with this client.
    if (clientData != NULL) {
        if (clientData->origin_resolution != NULL)
            freeaddrinfo(clientData->origin_resolution);
        free(clientData);
    }

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
    *(clientData->origin_resolution) = (struct addrinfo){
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_addr = (struct sockaddr*)sockaddr,
        .ai_addrlen = sizeof(*sockaddr),
    };
    char buf[BUFFER_SIZE] = {0};
    sockaddr_to_human(buf, BUFFER_SIZE, clientData->origin_resolution->ai_addr);

    printf("Hardcoding origin to %s\n", buf);

    stm_init(&clientData->stm);

    TSelectorStatus status = selector_register(key->s, newClientSocket, &handler, OP_READ, clientData);
    if (status != SELECTOR_SUCCESS) {
        printf("Failed to register new client into selector: %s\n", selector_error(status));
        free(clientData);
        return;
    }

    printf("New client registered successfully!\n");
}