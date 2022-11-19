#ifndef MGMT_H
#define MGMT_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "selector.h"
#include "buffer.h"
#include "stm.h"
#include "mgmtAuthParser.h"

#define MGMT_BUFFER_SIZE 4096

typedef struct {
    TFdHandler handler;

    struct state_machine stm;
    union {
        // TNegParser negParser;
        // TReqParser reqParser;
        MTAuthParser authParser;
    } client;

    bool closed;

    // Added this buffer, consider removing the plain buffer from this struct.
    struct buffer buffer;
    uint8_t rawBuffer[MGMT_BUFFER_SIZE];

    struct addrinfo* originResolution;
    int clientFd;

} TMgmtClient;

#define GET_ATTACHMENT(key) ((TMgmtClient*)(key)->data)

enum mgmt_state {
    /*

    */
    MGMT_AUTH_READ = 0,

    /*

    */
   
    MGMT_AUTH_WRITE,

    /*

    */
    MGMT_REQUEST_READ,

    /*

    */
   
    MGMT_REQUEST_WRITE,

    // estados terminales
    MGMT_DONE,
    MGMT_ERROR,

};

void mgmtPassiveAccept(TSelectorKey* key);

#endif