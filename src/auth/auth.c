#include "auth.h"
#include "../users.h"
#include "../logging/logger.h"
#include "../socks5.h"

void authReadInit(const unsigned state, TSelectorKey* key) {
    logf(LOG_DEBUG, "authReadInit: init at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);
    initAuthParser(&data->client.authParser);
}

unsigned authRead(TSelectorKey* key) {
    logf(LOG_DEBUG, "authRead: read at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->clientBuffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    logf(LOG_DEBUG, "authRead: %ld bytes from client %d", readCount, key->fd);
    if (readCount <= 0) {
        return ERROR;
    }

    buffer_write_adv(&data->clientBuffer, readCount);
    authParse(&data->client.authParser, &data->clientBuffer);
    if (hasAuthReadEnded(&data->client.authParser)) {
        TAuthParser* authpdata = &data->client.authParser;
        TUserPrivilegeLevel upl;
        TUserStatus userStatus = validateUserAndPassword(authpdata, &upl);

        switch (userStatus) {
            case EUSER_OK:
                logf(LOG_INFO, "Client %d successfully authenticated as %s (%s)", key->fd, authpdata->uname, usersPrivilegeToString(upl));
                break;
            case EUSER_WRONGUSERNAME:
                logf(LOG_INFO, "Client %d attempted to authenticate as %s but there's no such username", key->fd, authpdata->uname);
                break;
            case EUSER_WRONGPASSWORD:
                logf(LOG_INFO, "Client %d attempted to authenticate as %s but had the wrong password", key->fd, authpdata->uname);
                break;
            default:

                break;
        }

        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillAuthAnswer(&data->client.authParser, &data->originBuffer)) {
            return ERROR;
        }
        return AUTH_WRITE;
    }
    return AUTH_READ;
}

unsigned authWrite(TSelectorKey* key) {
    logf(LOG_DEBUG, "authWrite: send at fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t writeLimit;    // how many bytes we want to send
    ssize_t writeCount;   // how many bytes where written
    uint8_t* writeBuffer; // buffer that stores the data to be sended

    writeBuffer = buffer_read_ptr(&data->originBuffer, &writeLimit);
    writeCount = send(key->fd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        logf(LOG_ERROR, "authWrite: send() at fd %d", key->fd);
        return ERROR;
    }
    if (writeCount == 0) {
        logf(LOG_ERROR, "authWrite: Failed to send(), client closed connection unexpectedly at fd %d", key->fd);
        return ERROR;
    }
    logf(LOG_DEBUG, "authWrite: %ld bytes to client %d", writeCount, key->fd);
    buffer_read_adv(&data->originBuffer, writeCount);

    if (buffer_can_read(&data->originBuffer)) {
        return AUTH_WRITE;
    }

    if (hasAuthReadErrors(&data->client.authParser) || data->client.authParser.verification == AUTH_ACCESS_DENIED || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }

    logf(LOG_INFO, "Client %d has selected authentication method: NONE", key->fd);
    return REQUEST_READ;
}
