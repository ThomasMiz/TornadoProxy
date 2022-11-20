
#include "negotiation.h"
#include "../logging/logger.h"
#include "../socks5.h"
#include <stdio.h>

void negotiationReadInit(const unsigned state, TSelectorKey* key) {
    logf(LOG_DEBUG, "negotiationReadInit: init at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);
    initNegotiationParser(&data->client.negParser);
}

unsigned negotiationRead(TSelectorKey* key) {
    logf(LOG_DEBUG, "negotiationRead: read at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->clientBuffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    logf(LOG_DEBUG, "negotiationRead: %ld bytes from client %d ", readCount, key->fd);
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
    logf(LOG_DEBUG, "negotiationWrite: send at fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t writeLimit;    // how many bytes we want to send
    ssize_t writeCount;   // how many bytes where written
    uint8_t* writeBuffer; // buffer that stores the data to be sended

    writeBuffer = buffer_read_ptr(&data->originBuffer, &writeLimit);
    writeCount = send(key->fd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        logf(LOG_ERROR, "negotiationWrite: send() at fd %d", key->fd);
        return ERROR;
    }
    if (writeCount == 0) {
        logf(LOG_ERROR, "negotiationWrite: Failed to send(), client closed connection unexpectedly at fd %d", key->fd);
        return ERROR;
    }
    logf(LOG_DEBUG, "negotiationWrite: %ld bytes to client %d", writeCount, key->fd);
    buffer_read_adv(&data->originBuffer, writeCount);

    if (buffer_can_read(&data->originBuffer)) {
        return NEGOTIATION_WRITE;
    }

    if (hasNegotiationErrors(&data->client.negParser) || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }

    if (NEG_METHOD_PASS == data->client.negParser.authMethod) {
        return AUTH_READ;
    }
    return REQUEST_READ;
}
