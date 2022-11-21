#include "mgmtRequest.h"
#include "../logging/logger.h"
#include "../logging/metrics.h"
#include "../negotiation/negotiationParser.h"
#include "../passwordDissector.h"
#include "../users.h"
#include "mgmt.h"
#include "mgmtCmdParser.h"

void mgmtRequestReadInit(const unsigned state, TSelectorKey* key) {
    logf(LOG_DEBUG, "mgmtRequestReadInit: init at socket fd %d", key->fd);
    TMgmtClient* data = GET_ATTACHMENT(key);
    initMgmtCmdParser(&data->client.cmdParser);
}
unsigned mgmtRequestRead(TSelectorKey* key) {
    logf(LOG_DEBUG, "mgmtRequestRead: read at socket fd %d", key->fd);
    TMgmtClient* data = GET_ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->readBuffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    logf(LOG_DEBUG, "mgmtRequestRead: %ld bytes from client %d", readCount, key->fd);
    if (readCount <= 0) {
        return MGMT_ERROR;
    }

    buffer_write_adv(&data->readBuffer, readCount);
    mgmtCmdParse(&data->client.cmdParser, &data->readBuffer);
    if (hasMgmtCmdReadEnded(&data->client.cmdParser)) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillMgmtCmdAnswer(&data->client.cmdParser, &data->writeBuffer)) {
            return MGMT_ERROR;
        }
        data->cmd = data->client.cmdParser.cmd;
        return MGMT_REQUEST_WRITE;
    }
    return MGMT_REQUEST_READ;
}

static void handleUserCmdResponse(buffer* buffer, TMgmtParser* p, int fd) {
    logf(LOG_INFO, "Management client %d requested command USERS", fd);
    char toFill[USERS_MAX_USERNAME_LENGTH][USERS_MAX_COUNT];

    uint8_t len = fillCurrentUsers(toFill);
    uint8_t* ptr;
    size_t size;
    char* s = "+OK listing users:\n";
    int sLen = strlen(s);
    ptr = buffer_write_ptr(buffer, &size);
    memcpy(ptr, s, sLen);
    buffer_write_adv(buffer, sLen);
    for (uint8_t i = 0; i < len; i++) {
        ptr = buffer_write_ptr(buffer, &size);
        int nameLength = strlen(toFill[i]);
        memcpy(ptr, toFill[i], nameLength);
        int last = i == len - 1;
        if (!last)
            ptr[nameLength] = '\n';
        buffer_write_adv(buffer, nameLength + !last);
    }
}

static int roleMatches(int role) {
    switch (role) {
        case UPRIV_USER:
            return UPRIV_USER;
        case UPRIV_ADMIN:
            return UPRIV_ADMIN;
        default:
            return -1;
    }
}

static void handleAddUserCmdResponse(buffer* buffer, TMgmtParser* p, int fd) {
    logf(LOG_INFO, "Management client %d requested command ADD-USER", fd);
    size_t size;
    uint8_t* ptr = buffer_write_ptr(buffer, &size);
    char* username = p->args[0].string;
    char* password = p->args[1].string;
    int role = p->args[2].byte;

    static const char* successMessage = "+OK user successfully added";
    static const char* userAlreadyExistMessage = "-ERR user already exists";
    static const char* credentialsTooLong = "-ERR credentials too long";
    static const char* limitReachedMessage = "-ERR users limit reached";
    static const char* noMemoryMessage = "-ERR no memory";
    static const char* badRoleMessage = "-ERR role doesn't exist";
    static const char* unkownErrorMessage = "-ERR can't add user, try again";

    const char* toReturn = NULL;

    role = roleMatches(role);

    if (role < 0)
        toReturn = badRoleMessage;

    if (toReturn == NULL) {
        TUserStatus status = usersCreate(username, password, false, role == 0 ? UPRIV_USER : UPRIV_ADMIN, false);

        switch (status) {
            case EUSER_OK:
                toReturn = successMessage;
                break;
            case EUSER_ALREADYEXISTS:
                toReturn = userAlreadyExistMessage;
                break;
            case EUSER_CREDTOOLONG:
                toReturn = credentialsTooLong;
                break;
            case EUSER_LIMITREACHED:
                toReturn = limitReachedMessage;
                break;
            case EUSER_NOMEMORY:
                toReturn = noMemoryMessage;
                break;
            default:
                toReturn = unkownErrorMessage;
        }
    }

    strcpy((char*)ptr, toReturn);
    buffer_write_adv(buffer, strlen(toReturn));
}

static void handleDeleteUserCmdResponse(buffer* buffer, TMgmtParser* p, int fd) {
    logf(LOG_INFO, "Management client %d requested command DELETE-USER", fd);
    size_t size;
    uint8_t* ptr = buffer_write_ptr(buffer, &size);
    char* username = p->args[0].string;

    static const char* wrongUsernameMessage = "-ERR user doesn't exist";
    static const char* badOperationMessage = "-ERR cannot delete user because no other admins exist";
    static const char* successMessage = "+OK user successfully deleted";
    static const char* unkownErrorMessage = "-ERR can't delete user, try again";

    const char* toReturn;

    int status = usersDelete(username);

    switch (status) {
        case EUSER_OK:
            toReturn = successMessage;
            break;
        case EUSER_WRONGUSERNAME:
            toReturn = wrongUsernameMessage;
            break;
        case EUSER_BADOPERATION:
            toReturn = badOperationMessage;
            break;
        default:
            toReturn = unkownErrorMessage;
    }

    strcpy((char*)ptr, toReturn);
    buffer_write_adv(buffer, strlen(toReturn));
}

static void handleChangePasswordCmdResponse(buffer* buffer, TMgmtParser* p, int fd) {
    logf(LOG_INFO, "Management client %d requested command CHANGE-PASSWORD", fd);
    size_t size;
    uint8_t* ptr = buffer_write_ptr(buffer, &size);
    char* username = p->args[0].string;
    char* password = p->args[1].string;

    static const char* successMessage = "+OK password succesfully changed";
    static const char* credentialsTooLong = "-ERR credentials too long";
    static const char* badPassword = "-ERR bad password";
    static const char* noMemoryMessage = "-ERR no memory";
    static const char* wrongUsernameMessage = "-ERR user doesn't exist";
    static const char* unkownErrorMessage = "-ERR can't change password, try again";

    const char* toReturn;

    if (!userExists(username)) {
        toReturn = wrongUsernameMessage;
    } else {
        TUserStatus status = usersCreate(username, password, true, 0, false);

        switch (status) {
            case EUSER_OK:
                toReturn = successMessage;
                break;
            case EUSER_CREDTOOLONG:
                toReturn = credentialsTooLong;
                break;
            case EUSER_BADPASSWORD:
                toReturn = badPassword;
                break;
            case EUSER_NOMEMORY:
                toReturn = noMemoryMessage;
                break;
            default:
                toReturn = unkownErrorMessage;
        }
    }

    strcpy((char*)ptr, toReturn);
    buffer_write_adv(buffer, strlen(toReturn));
}

static void handleChangeRoleCmdResponse(buffer* buffer, TMgmtParser* p, int fd) {
    logf(LOG_INFO, "Management client %d requested command CHANGE-ROLE", fd);
    size_t size;
    uint8_t* ptr = buffer_write_ptr(buffer, &size);
    char* username = p->args[0].string;
    int role = p->args[1].byte;

    static const char* wrongUsernameMessage = "-ERR user doesn't exist";
    static const char* badOperationMessage = "-ERR cannot change role because no other admins exist";
    static const char* successMessage = "+OK user successfully changed role";
    static const char* unkownErrorMessage = "-ERR can't change user role, try again";
    static const char* badRoleMessage = "-ERR role doesn't exist";

    const char* toReturn = NULL;

    role = roleMatches(role);

    if (role < 0)
        toReturn = badRoleMessage;
    else if (!userExists(username))
        toReturn = wrongUsernameMessage;
    else if (toReturn == NULL) {
        TUserStatus status = usersCreate(username, NULL, false, role == 1 ? UPRIV_ADMIN : UPRIV_USER, true);
        switch (status) {
            case EUSER_OK:
                toReturn = successMessage;
                break;
            case EUSER_WRONGUSERNAME:
                toReturn = wrongUsernameMessage;
                break;
            case EUSER_BADOPERATION:
                toReturn = badOperationMessage;
                break;
            default:
                toReturn = unkownErrorMessage;
        }
    }

    strcpy((char*)ptr, toReturn);
    buffer_write_adv(buffer, strlen(toReturn));
}

static void handleGetDissectorStatusCmdResponse(buffer* buffer, TMgmtParser* p, int fd) {
    logf(LOG_INFO, "Management client %d requested command GET-DISSECTOR-STATUS", fd);
    size_t size;
    uint8_t* ptr = buffer_write_ptr(buffer, &size);
    static const char* on = "+OK dissector status: on";
    static const char* off = "+OK dissector status: off";
    int len;
    if (isPDissectorOn()) {
        len = strlen(on);
        strcpy((char*)ptr, on);
    } else {
        len = strlen(off);
        strcpy((char*)ptr, off);
    }
    buffer_write_adv(buffer, len);
}

static void handleSetDissectorStatusCmdResponse(buffer* buffer, TMgmtParser* p, int fd) {
    logf(LOG_INFO, "Management client %d requested command SET-DISSECTOR-STATUS", fd);
    size_t size;
    uint8_t turnOn = p->args[0].byte; // OFF = 0 : ON != 0

    uint8_t* ptr = buffer_write_ptr(buffer, &size);
    static const char* on = "+OK dissector status: on";
    static const char* off = "+OK dissector status: off";
    int len;
    if (!turnOn) {
        turnOffPDissector();
        len = strlen(off);
        strcpy((char*)ptr, off);
    } else {
        turnOnPDissector();
        len = strlen(on);
        strcpy((char*)ptr, on);
    }
    buffer_write_adv(buffer, len);
}

static void copyMetric(buffer* buffer, const char* metricString, size_t metricValue) {
    size_t size;
    char* ptr = (char*)buffer_write_ptr(buffer, &size);

    int len = strlen(metricString);
    memcpy(ptr, metricString, len);

    len += snprintf(ptr + len, size - len, "%ld\n", metricValue);
    buffer_write_adv(buffer, len);
}

static void handleStatisticsCmdResponse(buffer* buffer, TMgmtParser* p, int fd) {
    logf(LOG_INFO, "Management client %d requested command STATISTICS", fd);
    TMetricsSnapshot metrics;
    getMetricsSnapshot(&metrics);

    static const char* successMessage = "+OK showing stats:\n";
    int sucLength = strlen(successMessage);

    static const char* connectionCount = "CONC:";
    static const char* maxConcurrmetrics = "MCONC:";
    static const char* totalBytesRecv = "TBRECV:";
    static const char* totalBytesSent = "TBSENT:";
    static const char* totalConnectionCount = "TCON:";

    const char* statsString[] = {connectionCount, maxConcurrmetrics, totalBytesRecv, totalBytesSent, totalConnectionCount};
    size_t stats[] = {metrics.currentConnectionCount, metrics.maxConcurrentConnections, metrics.totalBytesReceived, metrics.totalBytesSent, metrics.totalConnectionCount};

    size_t size;

    // char statistics[64];
    uint8_t* ptr = buffer_write_ptr(buffer, &size);
    memcpy(ptr, successMessage, sucLength);
    buffer_write_adv(buffer, sucLength);

    for (int i = 0; i < (int)(sizeof(statsString) / sizeof(statsString[0])); i++)
        copyMetric(buffer, statsString[i], stats[i]);
}

static void handleGetAuthenticationStatusCmdResponse(buffer* buffer, TMgmtParser* p, int fd) {
    logf(LOG_INFO, "Management client %d requested command GET-AUTHENTICATION-STATUS", fd);
    size_t size;
    uint8_t* ptr = buffer_write_ptr(buffer, &size);

    static const char* noAuthMethod = "+OK authentication method: no authentication";
    static const char* passwordMethod = "+OK authentication method: username/password required";
    static const char* unkownErrorMessage = "-ERR can't fetch authentication method, try again later";
    static const char* toReturn;
    uint8_t status = getAuthMethod();

    switch (status) {
        case NEG_METHOD_NO_AUTH:
            toReturn = noAuthMethod;
            break;
        case NEG_METHOD_PASS:
            toReturn = passwordMethod;
            break;
        default:
            toReturn = unkownErrorMessage;
    }

    strcpy((char*)ptr, toReturn);
    buffer_write_adv(buffer, strlen(toReturn));
}

static void handleSetAuthenticationStatusCmdResponse(buffer* buffer, TMgmtParser* p, int fd) {
    logf(LOG_INFO, "Management client %d requested command SET-AUTHENTICATION-STATUS", fd);
    size_t size;
    uint8_t turnOn = p->args[0].byte; // OFF = 0 : ON != 0

    uint8_t* ptr = buffer_write_ptr(buffer, &size);
    static const char* noAuthMethod = "+OK authentication method: no authentication";
    static const char* passwordMethod = "+OK authentication method: username/password required";
    int len;
    if (turnOn) {
        changeAuthMethod(NEG_METHOD_PASS);
        len = strlen(passwordMethod);
        strcpy((char*)ptr, passwordMethod);
    } else {
        changeAuthMethod(NEG_METHOD_NO_AUTH);
        len = strlen(noAuthMethod);
        strcpy((char*)ptr, noAuthMethod);
    }
    buffer_write_adv(buffer, len);
}

static void handleUnknownCmd(buffer* buffer, TMgmtParser* p) {
    size_t size;

    uint8_t* ptr = buffer_write_ptr(buffer, &size);
    static const char* uknCommand = "-ERR unknown command";

    size = strlen(uknCommand);
    strcpy((char*)ptr, uknCommand);

    buffer_write_adv(buffer, size);
}

typedef void (*cmdHandler)(buffer* buffer, TMgmtParser* p, int fd);

static uint8_t isValidCmd(uint8_t cmd) {
    return cmd <= MGMT_CMD_STATISTICS;
}

static cmdHandler handlers[] = {
    /* MGMT_CMD_USERS                       */ handleUserCmdResponse,
    /* MGMT_CMD_ADD_USER                    */ handleAddUserCmdResponse,
    /* MGMT_CMD_DELETE_USER,                */ handleDeleteUserCmdResponse,
    /* MGMT_CMD_CHANGE_PASSWORD,            */ handleChangePasswordCmdResponse,
    /* MGMT_CMD_CHANGE_ROLE,                */ handleChangeRoleCmdResponse,
    /* MGMT_CMD_GET_DISSECTOR_STATUS,       */ handleGetDissectorStatusCmdResponse,
    /* MGMT_CMD_SET_DISSECTOR_STATUS,       */ handleSetDissectorStatusCmdResponse,
    /* MGMT_CMD_GET_AUTHENTICATION_STATUS,  */ handleGetAuthenticationStatusCmdResponse,
    /* MGMT_CMD_SET_AUTHENTICATION_STATUS,  */ handleSetAuthenticationStatusCmdResponse,
    /* MGMT_CMD_STATISTICS                  */ handleStatisticsCmdResponse};

void mgmtRequestWriteInit(const unsigned int st, TSelectorKey* key) {
    TMgmtClient* data = GET_ATTACHMENT(key);
    buffer_init(&(data->writeBuffer), MGMT_BUFFER_SIZE, data->writeRawBuffer);
    if (isValidCmd(data->cmd)) {
        handlers[data->cmd](&data->writeBuffer, &data->client.cmdParser, key->fd);
    } else {
        logf(LOG_INFO, "Management client %d requested unknown command", key->fd);
        handleUnknownCmd(&data->writeBuffer, &data->client.cmdParser);
    }
}

unsigned mgmtRequestWrite(TSelectorKey* key) {
    logf(LOG_DEBUG, "mgmtRequestWrite: send at fd %d", key->fd);
    TMgmtClient* data = GET_ATTACHMENT(key);

    size_t writeLimit;      // how many bytes we want to send
    ssize_t writeCount = 0; // how many bytes where written
    uint8_t* writeBuffer;   // buffer that stores the data to be sended

    // new
    writeBuffer = buffer_read_ptr(&data->writeBuffer, &writeLimit);
    writeCount = send(key->fd, writeBuffer, writeLimit, MSG_NOSIGNAL);
    logf(LOG_DEBUG, "mgmtRequestWrite: sent %ld bytes", writeCount);

    // ----

    // writeBuffer = buffer_read_ptr(&data->writeBuffer, &writeLimit);
    // writeCount = send(key->fd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        logf(LOG_ERROR, "mgmtRequestWrite: send() at fd %d", key->fd);
        return MGMT_ERROR;
    }
    if (writeCount == 0) {
        logf(LOG_ERROR, "mgmtRequestWrite: Failed to send(), client closed connection unexpectedly at fd %d", key->fd);
        return MGMT_ERROR;
    }
    logf(LOG_DEBUG, "mgmtRequestWrite: %ld bytes to client %d", writeCount, key->fd);
    buffer_read_adv(&data->writeBuffer, writeCount);

    if (buffer_can_read(&data->writeBuffer)) {
        return MGMT_REQUEST_WRITE;
    }

    if (hasMgmtCmdErrors(&data->client.cmdParser)) {
        return MGMT_ERROR;
    }
    return MGMT_DONE;
}