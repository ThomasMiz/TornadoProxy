#ifndef MGMT_H
#define MGMT_H

#include "../auth/authParser.h"
#include "../buffer.h"
#include "../selector.h"
#include "../stm.h"
#include "mgmtCmdParser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MGMT_BUFFER_SIZE 4096

typedef struct {
    struct state_machine stm;

    union {
        TMgmtParser cmdParser;
        TAuthParser authParser;
    } client;

    bool closed;

    TMgmtCmd cmd;
    int clientFd;

    struct buffer readBuffer;
    struct buffer writeBuffer;
    uint8_t readRawBuffer[MGMT_BUFFER_SIZE];
    uint8_t writeRawBuffer[MGMT_BUFFER_SIZE];
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

/**
 * @brief Handler to accept connections for server monitoring
 * @param key Selector key that holds information regarding the ready fd
 */
void mgmtPassiveAccept(TSelectorKey* key);

#endif
