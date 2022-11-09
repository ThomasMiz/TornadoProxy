
#include "negotiation.h"
#include "socks5.h"
#include <stdio.h>

void negotiationReadInit(const unsigned state, TSelectorKey* key) {
    printf("[Neg read] init at socket fd %d\n", key->fd);
    TClientData* data = ATTACHMENT(key);
    initNegotiationParser(&data->client.negParser);
}

unsigned negotiationRead(TSelectorKey* key) {
    printf("[Neg read: INF] read at socket fd %d\n", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->clientBuffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    printf("[Neg read: INF]  %ld bytes from client %d \n", readCount, key->fd);
    if (readCount <= 0) {
        return ERROR;
    }

    buffer_write_adv(&data->clientBuffer, readCount);
    negotiationParse(&data->client.negParser, &data->clientBuffer);
    if (hasNegotiationReadEnded(&data->client.negParser)) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillNegotiationAnswer(&data->client.negParser, &data->originBuffer)) {
            return ERROR;
        }
        return NEGOTIATION_WRITE;
    }
    return NEGOTIATION_READ;
}

unsigned negotiationWrite(TSelectorKey* key) {
    printf("[Neg write: INF] send at fd %d\n", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t writeLimit;    // how many bytes we want to send
    ssize_t writeCount;   // how many bytes where written
    uint8_t* writeBuffer; // buffer that stores the data to be sended

    writeBuffer = buffer_read_ptr(&data->originBuffer, &writeLimit);
    writeCount = send(key->fd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        perror("[Neg write: ERR] send()");
        return ERROR;
    }
    if (writeCount == 0) {
        printf("[Neg write: ERR] Failed to send(), client closed connection unexpectedly\n");
        return ERROR;
    }
    printf("[Neg write: INF]  %ld bytes to client %d \n", writeCount, key->fd);
    buffer_read_adv(&data->originBuffer, writeCount);

    if (buffer_can_read(&data->originBuffer)) {
        return NEGOTIATION_WRITE;
    }

    if (hasNegotiationErrors(&data->client.negParser) || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }

    return REQUEST_READ;
}
