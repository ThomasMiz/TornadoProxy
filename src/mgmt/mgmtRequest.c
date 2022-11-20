#include "mgmtRequest.h"
#include "../passwordDissector.h"
#include "mgmtCmdParser.h"
#include "../logger.h"
#include "mgmt.h"
#include "mgmtCmdParser.h"


void mgmtRequestReadInit(const unsigned state, TSelectorKey* key){
    log(DEBUG, "[Mgmt req read] init at socket fd %d", key->fd);
    TMgmtClient* data = GET_ATTACHMENT(key);
    initMgmtCmdParser(&data->client.cmdParser);
}
unsigned mgmtRequestRead(TSelectorKey* key){
    log(DEBUG, "[Mgmt req read] read at socket fd %d", key->fd);
    TMgmtClient* data = GET_ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->readBuffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    log(DEBUG, "[Mgmt req read]  %ld bytes from client %d", readCount, key->fd);
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

static void handleUserCmdResponse(buffer * buffer) {
    size_t size;
    uint8_t * ptr = buffer_write_ptr(buffer, &size);
    char * s = "users response\r\n";
    int len = strlen(s);
    strcpy((char *)ptr, s);
    
    // Esto se tiene que poder escribir si o si porque es un buffer que recien inicializamos
    buffer_write_adv(buffer, len);
}

static void handleGetDissectorStatusCmdResponse(buffer * buffer) {
    size_t size;
    uint8_t * ptr = buffer_write_ptr(buffer, &size);
    static char * on = "+OK. Password dissector is on\n";
    static char * off = "+OK. Password dissector is off\n";
    int len;
    if(isPDissectorOn()){
        len = strlen(on);
        strcpy((char *)ptr, on);
    }else{
        len = strlen(off);
        strcpy((char *)ptr, off);
    }
    buffer_write_adv(buffer, len);
}

void mgmtRequestWriteInit(const unsigned int st, TSelectorKey* key) {
    TMgmtClient * data = GET_ATTACHMENT(key);
    buffer_init(&(data->responseBuffer), MGMT_BUFFER_SIZE, data->responseRawBuffer);
   size_t size;
    
    if (data->cmd == MGMT_CMD_USERS) { // ACA habria que llenar el buffer de respuesta con el string que corresponde al comando
        handleUserCmdResponse(&data->responseBuffer);
    } else {
        // los otros comandos
    }
}

unsigned mgmtRequestWrite(TSelectorKey* key){
    log(DEBUG, "[Mgmt req write] send at fd %d", key->fd);
    TMgmtClient* data = GET_ATTACHMENT(key);

    size_t writeLimit;    // how many bytes we want to send
    ssize_t writeCount = 0;   // how many bytes where written
    uint8_t* writeBuffer; // buffer that stores the data to be sended

 // new
    writeBuffer = buffer_read_ptr(&data->responseBuffer, &writeLimit);
    writeCount = send(key->fd, writeBuffer, writeLimit, MSG_NOSIGNAL);
    buffer_read_adv(&data->responseBuffer, writeCount);
    log(DEBUG, "[Mgmt req write] sent %ld bytes", writeCount);

// ----

    // writeBuffer = buffer_read_ptr(&data->writeBuffer, &writeLimit);
    // writeCount = send(key->fd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        log(LOG_ERROR, "[Mgmt req write] send() at fd %d", key->fd);
        return MGMT_ERROR;
    }
    if (writeCount == 0) {
        log(LOG_ERROR, "[Mgmt req write] Failed to send(), client closed connection unexpectedly at fd %d", key->fd);
        return MGMT_ERROR;
    }
    log(DEBUG, "[Mgmt req write]  %ld bytes to client %d", writeCount, key->fd);
    buffer_read_adv(&data->responseBuffer, writeCount);

    if (buffer_can_read(&data->responseBuffer)) {
        return MGMT_REQUEST_WRITE;
    }

    if (hasMgmtCmdErrors(&data->client.cmdParser)) {
        return MGMT_ERROR;
    }
    return MGMT_DONE;
}