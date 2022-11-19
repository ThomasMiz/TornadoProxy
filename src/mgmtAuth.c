#include "mgmtAuth.h"
#include "logger.h"
#include "users.h"
#include "mgmtAuthParser.h"
#include "mgmt.h"

static TUserStatus mgmtValidateUserAndPassword(MTAuthParser* p) {
    TUserPrivilegeLevel upl;
    TUserStatus userStatus = usersLogin(p->uname, p->passwd, &upl);
    if (userStatus == EUSER_OK) {
        p->verification = M_AUTH_SUCCESSFUL;
    }
    return userStatus;
}

void mgmtAuthReadInit(const unsigned state, TSelectorKey* key) {
    log(DEBUG, "[Mgmt Auth read] init at socket fd %d", key->fd);
    TMgmtClient* data = GET_ATTACHMENT(key);
    mgmtInitAuthParser(&data->client.authParser);
}

unsigned mgmtAuthRead(TSelectorKey* key) {
    log(DEBUG, "[Mgmt Auth read] read at socket fd %d", key->fd);
    TMgmtClient* data = GET_ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->buffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    log(DEBUG, "[Mgmt Auth read]  %ld bytes from client %d", readCount, key->fd);
    if (readCount <= 0) {
        return MGMT_ERROR;
    }

    buffer_write_adv(&data->buffer, readCount);
    mgmtAuthParse(&data->client.authParser, &data->buffer);
    if (mgmtHasAuthReadEnded(&data->client.authParser)) {
        mgmtValidateUserAndPassword(&data->client.authParser);
        // if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillAuthAnswer(&data->client.authParser, &data->originBuffer)) {
        //     return MGMT_ERROR;
        // }
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

    // writeBuffer = buffer_read_ptr(&data->originBuffer, &writeLimit);
    // writeCount = send(key->fd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        log(LOG_ERROR, "[Mgmt Auth write] send() at fd %d", key->fd);
        return MGMT_ERROR;
    }
    if (writeCount == 0) {
        log(LOG_ERROR, "[Mgmt Auth write] Failed to send(), client closed connection unexpectedly at fd %d", key->fd);
        return MGMT_ERROR;
    }
    log(DEBUG, "[Mgmt Auth write]  %ld bytes to client %d", writeCount, key->fd);
    // buffer_read_adv(&data->originBuffer, writeCount);

    // if (buffer_can_read(&data->originBuffer)) {
    //     return MGMT_AUTH_WRITE;
    // }

    if (mgmtHasAuthReadErrors(&data->client.authParser)|| data->client.authParser.verification == M_AUTH_ACCESS_DENIED || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return MGMT_ERROR;
    }

    return MGMT_REQUEST_READ;
}
