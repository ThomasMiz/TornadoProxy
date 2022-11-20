#include "copy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "logging/logger.h"
#include "socks5.h"

#define CLIENT_NAME "client"
#define ORIGIN_NAME "origin"

static TFdInterests getInterests(TSelector s, TCopy * copy) {
    TFdInterests ret = OP_NOOP;
    if ((copy->duplex & OP_READ) && buffer_can_write(copy->otherBuffer)) {
        ret |= OP_READ;
    }
    if ((copy->duplex & OP_WRITE) && buffer_can_read(copy->targetBUffer)) {
        ret |= OP_WRITE;
    }
    if (SELECTOR_SUCCESS != selector_set_interest(s, *copy->targetFd, ret)) {
        logf(LOG_DEBUG, "Selector returned error when setting interests on fd %d", *copy->targetFd);
        abort();
    }
    return ret;
}

static unsigned copyReadHandler(TClientData* clientData, TCopy * copy) {
    int targetFd = *copy->targetFd;
    int otherFd = *copy->otherFd;
    TSelector s = copy->s;
    buffer * otherBuffer = copy->otherBuffer;
    char * name = copy->name;
    logf(LOG_DEBUG, "copyReadHandler: Reading from fd %s %d", name, targetFd);
    size_t capacity;
    size_t remaining;

    if (!buffer_can_write(otherBuffer)) {
        return COPY;
    }

    u_int8_t* writePtr = buffer_write_ptr(otherBuffer, &(capacity));

    ssize_t readBytes = recv(targetFd, writePtr, capacity, 0);

    if (readBytes > 0) {
        buffer_write_adv(otherBuffer, readBytes);
        buffer_write_ptr(otherBuffer, &(remaining));
        logf(LOG_DEBUG, "copyReadHandler: recv() %ld bytes from %s %d (remaining buffer capacity %lu)", readBytes, name, targetFd, remaining);

        if(clientData->pDissector.isOn){
            parseUserData(&clientData->pDissector, otherBuffer, targetFd);
        }
    }

    else { // EOF or err
        logf(LOG_DEBUG, "copyReadHandler: recv() returned %ld, closing %s %d", readBytes, name, targetFd);
        shutdown(targetFd, SHUT_RD);
        copy->duplex &= ~OP_READ;
        if (otherFd != -1) {
            shutdown(*(copy->otherFd), SHUT_WR);
            *(copy->otherDuplex) &= ~OP_WRITE;
        }
    }

    getInterests(s,copy);
    getInterests(s,copy->otherCopy);
    if(copy->duplex == OP_NOOP ){
        return DONE;
    }
    return COPY;
}

static unsigned copyWriteHandler(TCopy * copy) {
    int targetFd = *copy->targetFd;
    TSelector s = copy->s;
    buffer * targetBuffer = copy->targetBUffer;
    char * name = copy->name;

    logf(LOG_DEBUG, "copyWriteHandler: Writing to fd %s %d", name, targetFd);

    size_t capacity;
    ssize_t sent;
    if (!buffer_can_read(targetBuffer)) {
        return COPY;
    }
    uint8_t* readPtr = buffer_read_ptr(targetBuffer, &(capacity));
    sent = send(targetFd, readPtr, capacity, MSG_NOSIGNAL);
    if (sent <= 0) {
        logf(LOG_DEBUG, "copyWriteHandler: send() returned %ld, closing %s %d", sent, name, targetFd);
        shutdown(*(copy->targetFd), SHUT_WR);
        copy->duplex &= ~OP_WRITE;
        if (*(copy->otherFd) != -1) {
            shutdown(*(copy->otherFd), SHUT_RD);
            *(copy->otherDuplex) &= ~OP_READ;
        }
    } else {
        buffer_read_adv(targetBuffer, sent);
    }

    logf(LOG_DEBUG, "copyWriteHandler: send() %ld bytes to %s %d [%lu remaining]", sent, name, targetFd, capacity - sent);
    getInterests(s,copy);
    getInterests(s,copy->otherCopy);
    if(copy->duplex == OP_NOOP ){
        return DONE;
    }
    return COPY;
}

void socksv5HandleInit(const unsigned int st, TSelectorKey* key) {
    TClientData* data = ATTACHMENT(key);
    TConnection * connections = &(data->connections);
    int * clientFd = &data->clientFd;
    int * originFd = &data->originFd;
    TCopy* clientCopy = &(connections->clientCopy);
    clientCopy->targetFd = clientFd;
    clientCopy->otherFd = originFd;
    clientCopy->targetBUffer = &data->clientBuffer;
    clientCopy->otherBuffer = &data->originBuffer;
    clientCopy->name = CLIENT_NAME;
    clientCopy->s = key->s;
    clientCopy->duplex = OP_READ | OP_WRITE;
    selector_set_interest(key->s, *clientFd, OP_READ);

    TCopy* originCopy = &(connections->originCopy);
    originCopy->targetFd = originFd;
    originCopy->otherFd = clientFd;
    originCopy->targetBUffer = &data->originBuffer;
    originCopy->otherBuffer = &data->clientBuffer;
    originCopy->name = ORIGIN_NAME;
    originCopy->s = key->s;
    originCopy->duplex = OP_READ | OP_WRITE;
    selector_set_interest(key->s, *originFd, OP_READ);

    clientCopy->otherDuplex = &(originCopy->duplex);
    clientCopy->otherCopy = &(connections->originCopy);
    originCopy->otherDuplex = &(clientCopy->duplex);
    originCopy->otherCopy = &(connections->clientCopy);

    initPDissector(&data->pDissector, data->client.reqParser.port, data->clientFd, data->originFd);
}
unsigned socksv5HandleRead(TSelectorKey* key) {
    logf(LOG_DEBUG, "socksv5HandleRead: Reading from fd %d", key->fd);
    TClientData* clientData = key->data;
    TConnection* connections = &(clientData->connections);
    TCopy * copy;
    if (clientData->clientFd == key->fd) {
        copy = &(connections->clientCopy);
    } else { // fd == origin_fd
        copy = &(connections->originCopy);
    }
    return copyReadHandler(clientData, copy);
}

unsigned socksv5HandleWrite(TSelectorKey* key) {
    logf(LOG_DEBUG, "socksv5HandleWrite: Writing to fd %d", key->fd);
    TClientData* clientData = key->data;
    TConnection* connections = &(clientData->connections);
    TCopy * copy;
    if (clientData->clientFd == key->fd) {
        copy = &(connections->clientCopy);
    } else { // fd == origin_fd
        copy = &(connections->originCopy);
    }
    return copyWriteHandler(copy);
}

void socksv5HandleClose(const unsigned int state, TSelectorKey* key) {
    logf(LOG_DEBUG,"socksv5HandleClose: Client closed: %d", key->fd);
}
