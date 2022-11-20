#include "socks5.h"
#include "auth/auth.h"
#include "copy.h"
#include "request/request.h"
#include "selector.h"
#include "stm.h"
#include "logging/logger.h"
#include "logging/metrics.h"
#include "logging/util.h"
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void closeConnection(TSelectorKey * key);

void doneArrival(const unsigned state, TSelectorKey* key) {
    log(LOG_DEBUG, "Socks5: Done state");
}
void errorArrival(const unsigned state, TSelectorKey* key) {
    log(LOG_DEBUG, "Socks5: Error state");
}

static const struct state_definition clientActions[] = {
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
        .state = AUTH_READ,
        .on_arrival = authReadInit,
        .on_read_ready = authRead,
    },
    {
        .state = AUTH_WRITE,
        .on_write_ready = authWrite,
    },
    {
        .state = REQUEST_READ,
        .on_arrival = requestReadInit,
        .on_read_ready = requestRead,
    },
    {
        .state = REQUEST_RESOLV,
        .on_block_ready = requestResolveDone,
    },
    {
        .state = REQUEST_CONNECTING,
        .on_arrival = requestConectingInit,
        .on_write_ready = requestConecting,
    },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = requestWrite,
    },
    {
        .state = COPY,
        .on_arrival = socksv5HandleInit,
        .on_read_ready = socksv5HandleRead,
        .on_write_ready = socksv5HandleWrite,
        .on_departure = socksv5HandleClose,
    },
    {
        .state = DONE,
        .on_arrival = doneArrival,
    },
    {
        .state = ERROR,
        .on_arrival = errorArrival,
    }};

static void socksv5Read(TSelectorKey* key);
static void socksv5Write(TSelectorKey* key);
static void socksv5Close(TSelectorKey* key);
static void socksv5Block(TSelectorKey* key);
static TFdHandler handler = {
    .handle_read = socksv5Read,
    .handle_write = socksv5Write,
    .handle_close = socksv5Close,
    .handle_block = socksv5Block,
};

const TFdHandler* getStateHandler() {
    return &handler;
}

void socksv5Close(TSelectorKey* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    stm_handler_close(stm, key);
    closeConnection(key);
}

static void socksv5Read(TSelectorKey* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum socks_state st = stm_handler_read(stm, key);
    if(st == ERROR || st == DONE){
        closeConnection(key);
    }
}

static void socksv5Write(TSelectorKey* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum socks_state st = stm_handler_write(stm, key);
    if(st == ERROR || st == DONE){
        closeConnection(key);
    }
}

static void socksv5Block(TSelectorKey* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum socks_state st = stm_handler_block(stm, key);
    if(st == ERROR || st == DONE){
        closeConnection(key);
    }
}

void closeConnection(TSelectorKey * key) {
    TClientData * data = ATTACHMENT(key);
    if (data->closed)
        return;
    data->closed = true;
    metricsRegisterClientDisconnected();

    int clientSocket = data->clientFd;
    int serverSocket = data->originFd;

    if (serverSocket != -1) {
        selector_unregister_fd(key->s, serverSocket);
        close(serverSocket);
    }
    if (clientSocket != -1) {
        selector_unregister_fd(key->s, clientSocket);
        close(clientSocket);
    }

    if (data->originResolution != NULL) {
        if(data->client.reqParser.atyp != REQ_ATYP_DOMAINNAME){
            free(data->originResolution->ai_addr);
            free(data->originResolution);
        }else {
            freeaddrinfo(data->originResolution);
        }
    }

    free(data);
}

void socksv5PassivAccept(TSelectorKey* key) {
    struct sockaddr_storage clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);
    int newClientSocket = accept(key->fd, (struct sockaddr*)&clientAddress, &clientAddressLen);

    if(newClientSocket < 0) {
        logf(LOG_WARNING, "Socksv5 socket: accept() returned negative value: %d", newClientSocket);
        return;
    }

    if(newClientSocket > 1023){
        close(newClientSocket);
        logf(LOG_WARNING, "Socksv5 new client from %s with fd %d rejected because fd was too high", printSocketAddress((struct sockaddr*)&clientAddress), newClientSocket);
        return;
    }

    // Consider using a function to initialize the TClientData structure.
    TClientData* clientData = calloc(1, sizeof(TClientData));
    if (clientData == NULL) {
        logf(LOG_ERROR, "Socksv5 new client from %s with fd %d rejected because alloc failed for clientData", printSocketAddress((struct sockaddr*)&clientAddress), newClientSocket);
        close(newClientSocket);
        return;
    }

    clientData->stm.initial = NEGOTIATION_READ;
    clientData->stm.max_state = ERROR;
    clientData->closed = false;
    clientData->stm.states = clientActions;
    clientData->clientFd = newClientSocket;
    clientData->originFd=-1;

    buffer_init(&clientData->originBuffer, BUFFER_SIZE, clientData->inOriginBuffer);
    buffer_init(&clientData->clientBuffer, BUFFER_SIZE, clientData->inClientBuffer);

    stm_init(&clientData->stm);

    TSelectorStatus status = selector_register(key->s, newClientSocket, getStateHandler(), OP_READ, clientData);

    if (status != SELECTOR_SUCCESS) {
        logf(LOG_ERROR, "Socksv5 new client from %s with fd %d rejected because registering into selector failed: %s", printSocketAddress((struct sockaddr*)&clientAddress), newClientSocket, selector_error(status));
        close(newClientSocket);
        free(clientData);
        return;
    }
    
    metricsRegisterNewClient();
    logf(LOG_INFO, "Socksv5 new client from %s assigned id %d", printSocketAddress((struct sockaddr*)&clientAddress), newClientSocket);
}
