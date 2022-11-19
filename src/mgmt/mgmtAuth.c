#include "mgmtAuth.h"
#include "../logger.h"
#include "../users.h"
#include "mgmt.h"


void mgmtAuthReadInit(const unsigned state, TSelectorKey* key) {
    log(DEBUG, "[Mgmt Auth read] init at socket fd %d", key->fd);
    TMgmtClient* data = GET_ATTACHMENT(key);
    initAuthParser(&data->client.authParser);
}

unsigned mgmtAuthRead(TSelectorKey* key) {
    log(DEBUG, "[Mgmt Auth read] read at socket fd %d", key->fd);
    TMgmtClient* data = GET_ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->readBuffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    log(DEBUG, "[Mgmt Auth read]  %ld bytes from client %d", readCount, key->fd);
    if (readCount <= 0) {
        return MGMT_ERROR;
    }

    buffer_write_adv(&data->readBuffer, readCount);
    authParse(&data->client.authParser, &data->readBuffer);
    if (hasAuthReadEnded(&data->client.authParser)) {
        validateUserAndPassword(&data->client.authParser);
         if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillAuthAnswer(&data->client.authParser, &data->writeBuffer)) {
             return MGMT_ERROR;
         }
        return MGMT_AUTH_WRITE;
    }
    return MGMT_AUTH_READ;
}

unsigned mgmtAuthWrite(TSelectorKey* key) {
    log(DEBUG, "[Mgmt Auth write] send at fd %d", key->fd);
    TMgmtClient* data = GET_ATTACHMENT(key);

    size_t writeLimit;    // how many bytes we want to send
    ssize_t writeCount = 0;   // how many bytes where written
    uint8_t* writeBuffer; // buffer that stores the data to be sended

    writeBuffer = buffer_read_ptr(&data->writeBuffer, &writeLimit);
    writeCount = send(key->fd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        log(LOG_ERROR, "[Mgmt Auth write] send() at fd %d", key->fd);
        return MGMT_ERROR;
    }
    if (writeCount == 0) {
        log(LOG_ERROR, "[Mgmt Auth write] Failed to send(), client closed connection unexpectedly at fd %d", key->fd);
        return MGMT_ERROR;
    }
    log(DEBUG, "[Mgmt Auth write]  %ld bytes to client %d", writeCount, key->fd);
    buffer_read_adv(&data->writeBuffer, writeCount);

    if (buffer_can_read(&data->writeBuffer)) {
        return MGMT_AUTH_WRITE;
    }

    if (hasAuthReadErrors(&data->client.authParser)|| data->client.authParser.verification == AUTH_ACCESS_DENIED || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return MGMT_ERROR;
    }

    return MGMT_REQUEST_READ;
}
