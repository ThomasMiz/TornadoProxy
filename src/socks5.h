#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#include "auth/authParser.h"
#include "buffer.h"
#include "copy.h"
#include "negotiation/negotiation.h"
#include "passwordDissector.h"
#include "request/requestParser.h"
#include "selector.h"
#include "stm.h"
#include <netdb.h>
#include <stdbool.h>

// obtiene el struct socks5* desde la key
#define ATTACHMENT(key) ((TClientData*)(key)->data)
#define BUFFER_SIZE 32768
#define N(x) (sizeof(x) / sizeof((x)[0]))

typedef struct TClientData {
    struct state_machine stm;
    union {
        TNegParser negParser;
        TReqParser reqParser;
        TAuthParser authParser;
    } client;

    bool closed;

    TPDissector pDissector;

    // Added this buffer, consider removing the plain buffer from this struct.
    struct buffer clientBuffer;
    uint8_t inClientBuffer[BUFFER_SIZE];

    struct buffer originBuffer;
    uint8_t inOriginBuffer[BUFFER_SIZE];

    struct addrinfo* originResolution;
    int clientFd;
    // informacion del OS
    int originFd;

    TConnection connections;
} TClientData;

enum socks_state {

    /* Reads and processes the negotiation.
    Interests:
        - OP_READ -> client_fd
    Transitions:
        - HELLO_READ if the message was not completely read
        - HELLO_WRITE when the message is completely read
        - ERROR if an error occurs (IO/parsing) */
    NEGOTIATION_READ = 0,

    /* Sends the negotiation answer to the client
     Interests:
        - OP_WRITE -> client_fd
    Transitions:
        - HELLO_WRITE if there are bytes to be sended
        - AUTH_READ when all the bytes where sended, and authentication is required
        - REQUEST_READ when all the bytes where sended, and no authentication is required
        - ERROR if an error occurs (IO/parsing) */
    NEGOTIATION_WRITE,

    /* Reads and processes the client authentication.
    Interests:
        - OP_READ -> client_fd
    Transitions:
        - AUTH_READ if the message was not completely read
        - AUTH_WRITE when the message is completely read
        - ERROR if an error occurs (IO/parsing) */
    AUTH_READ,

    /* Sends the authentication answer to the client
    Interests:
       - OP_WRITE -> client_fd
    Transitions:
       - AUTH_WRITE if there are bytes to be sended
       - REQUEST_READ when all the bytes where sended, and the auth provided was valid
       - REQUEST_READ when all the bytes where sended, and no authentication is required
       - ERROR if an error occurs (IO/parsing) */
    AUTH_WRITE,

    /* Reads and processes the client request.
    Interests:
        - OP_READ -> client_fd
    Transitions:
        - REQUEST_READ if the message was not completely read
        - REQUEST_RESOLV if a DNS name needs to be resolved
        - REQUEST_CONNECTING if no DNS name needs to be resolved
        - REQUEST_WRITE if there were errors processing the request
        - ERROR if an error occurs (IO/parsing) */
    REQUEST_READ,

    /* Waits for a DNS resolution
    Interests:
        - OP_NOOP -> client_fd
    Transitions:
        - REQUEST_CONNECTING if the resolution was successful
        - REQUEST_WRITE otherwise */
    REQUEST_RESOLV,

    /* Waits util the connection is established
    Interests:
        - OP_WRITE -> client_fd
    Transitions:
        - REQUEST_WRITE when the connection is established
    */
    REQUEST_CONNECTING,

    /* Sends the request answer to the client
    Interests:
        - OP_WRITE -> client_fd
        - OP_NOOP -> origin_fd
    Transitions:
        - HELLO_WRITE if there are bytes to be sended
        - COPY if the request was successful
        - ERROR I/O error */
    REQUEST_WRITE,

    /* copies bytes between client_fd and origin_fd
    Interests:
        - OP_READ if there is enough space to write in the reading buffer
        - OP_WRITE if there are bytes to read from the writing buffer
    Transitions:
        - DONE when there is nothing else to copy */
    COPY,

    // Terminal states
    DONE,
    ERROR,
};

/**
 * @brief Handler to accept connections for socks server
 * @param key Selector key that holds information regarding the ready fd
 */
void socksv5PassivAccept(TSelectorKey* key);

/**
 * @brief Handler to return static function pointers handler for socks server
 * @returns The selector handler for read, write, block, close
 */
const TFdHandler* getStateHandler();

#endif
