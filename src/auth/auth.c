#include "auth.h"
#include "../logger.h"
#include "../socks5.h"
#include "../users.h"

static TAuthVerification validateUserAndPassword(TAuthParser* p) {
    TUserPrivilegeLevel upl;
    TUserStatus userStatus = usersLogin(p->uname, p->passwd, &upl);
    if (userStatus == EUSER_OK) {
        p->verification = AUTH_SUCCESSFUL;
    }
    return userStatus;
}

void authReadInit(const unsigned state, TSelectorKey* key) {
    log(DEBUG, "[Auth read] init at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);
    initAuthParser(&data->client.authParser);
}

unsigned authRead(TSelectorKey* key) {
    log(DEBUG, "[Auth read] read at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->clientBuffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    log(DEBUG, "[Auth read]  %ld bytes from client %d", readCount, key->fd);
    if (readCount <= 0) {
        return ERROR;
    }

    buffer_write_adv(&data->clientBuffer, readCount);
    authParse(&data->client.authParser, &data->clientBuffer);
    if (hasAuthReadEnded(&data->client.authParser)) {
        validateUserAndPassword(&data->client.authParser);
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillAuthAnswer(&data->client.authParser, &data->originBuffer)) {
            return ERROR;
        }
        return AUTH_WRITE;
    }
    return AUTH_READ;
}

unsigned authWrite(TSelectorKey* key) {
    log(DEBUG, "[Auth write] send at fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t writeLimit;    // how many bytes we want to send
    ssize_t writeCount;   // how many bytes where written
    uint8_t* writeBuffer; // buffer that stores the data to be sended

    writeBuffer = buffer_read_ptr(&data->originBuffer, &writeLimit);
    writeCount = send(key->fd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        log(LOG_ERROR, "[Auth write] send() at fd %d", key->fd);
        return ERROR;
    }
    if (writeCount == 0) {
        log(LOG_ERROR, "[Auth write] Failed to send(), client closed connection unexpectedly at fd %d", key->fd);
        return ERROR;
    }
    log(DEBUG, "[Auth write]  %ld bytes to client %d", writeCount, key->fd);
    buffer_read_adv(&data->originBuffer, writeCount);

    if (buffer_can_read(&data->originBuffer)) {
        return AUTH_WRITE;
    }

    if (hasAuthReadErrors(&data->client.authParser)|| data->client.authParser.verification == AUTH_ACCESS_DENIED || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }

    return REQUEST_READ;
}
