#include "request.h"
#include "socks5.h"
#include <stdio.h>

void requestReadInit(const unsigned state, TSelectorKey* key) {
    printf("[Req read] init at socket fd %d\n", key->fd);
    TClientData* data = ATTACHMENT(key);
    initRequestParser(&data->client.reqParser);
}

unsigned requestRead(TSelectorKey* key) {
    printf("[Req read: INF] read at socket fd %d\n", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->readBuffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    printf("[Req read: INF]  %ld bytes from client %d \n", readCount, key->fd);
    if (readCount <= 0) {
        return ERROR;
    }

    buffer_write_adv(&data->readBuffer, readCount);
    requestParse(&data->client.reqParser, &data->readBuffer);
    if (hasRequestReadEnded(&data->client.reqParser)) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillRequestAnswer(&data->client.reqParser, &data->writeBuffer)) {
            return ERROR;
        }
        return REQUEST_WRITE;
    }
    return REQUEST_READ;
}

unsigned requestWrite(TSelectorKey* key) {
    printf("[Req write: INF] send at fd %d\n", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t writeLimit;    // how many bytes we want to send
    ssize_t writeCount;   // how many bytes where written
    uint8_t* writeBuffer; // buffer that stores the data to be sended

    writeBuffer = buffer_read_ptr(&data->writeBuffer, &writeLimit);
    writeCount = send(key->fd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        perror("[Req write: ERR] send()");
        return ERROR;
    }
    if (writeCount == 0) {
        printf("[Req write: ERR] Failed to send(), client closed connection unexpectedly\n");
        return ERROR;
    }
    printf("[Req write: INF]  %ld bytes to client %d \n", writeCount, key->fd);
    buffer_read_adv(&data->writeBuffer, writeCount);

    if (buffer_can_read(&data->writeBuffer)) {
        return REQUEST_WRITE;
    }

    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }

    return COPY;
}