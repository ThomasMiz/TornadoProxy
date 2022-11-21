#ifndef MANAGEMENT_CMD_PARSER_H
#define MANAGEMENT_CMD_PARSER_H

#include "../buffer.h"
#include <stdbool.h>

#define MGMT_MAX_ARGS 3
#define MGMT_MAX_STRING_LENGTH 0xFF

typedef char TString[MGMT_MAX_STRING_LENGTH + 1];

typedef enum TMgmtCmd {
   MGMT_CMD_USERS = 0,
   MGMT_CMD_ADD_USER,
   MGMT_CMD_DELETE_USER,
   MGMT_CMD_CHANGE_PASSWORD,
   MGMT_CMD_CHANGE_ROLE,
   MGMT_CMD_GET_DISSECTOR,
   MGMT_CMD_SET_DISSECTOR,
   MGMT_CMD_GET_AUTHENTICATION_STATUS,
   MGMT_CMD_SET_AUTHENTICATION_STATUS,
   MGMT_CMD_STATISTICS
} TMgmtCmd;

typedef enum TMgmtState {
    MGMTP_WAITING_CMD,
    MGMTP_READING_ARGS,
    MGMTP_END,
    MGMTP_ERROR
}TMgmtState;

typedef enum TMgmtStatus {
    MGMT_SUCCESS,
    MGMT_INVALID_CMD,
    MGMT_INVALID_STRING_LENGTH
}TMgmtStatus;

typedef union TArg{
    uint8_t byte;
    TString string;
}TArg;

typedef struct TMgmtParser {
    TMgmtState state;
    TMgmtStatus status;
    TMgmtCmd cmd;

    uint8_t readArgs;

    uint8_t slength;    // Lenght to read from a string arg
    uint8_t rlength;    // Already read bytes form a string
    TArg args[MGMT_MAX_ARGS];
} TMgmtParser;


void initMgmtCmdParser(TMgmtParser* p);
TMgmtState mgmtCmdParse(TMgmtParser* p, struct buffer* buffer);
bool hasMgmtCmdReadEnded(TMgmtParser* p);
bool hasMgmtCmdErrors(TMgmtParser* p);
uint8_t fillMgmtCmdAnswer(TMgmtParser* p, struct buffer* buffer);

#endif // MANAGEMENT_CMD_PARSER_H