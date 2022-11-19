#ifndef MANAGEMENT_CMD_PARSER_H
#define MANAGEMENT_CMD_PARSER_H

#include "buffer.h"
#include <stdbool.h>

#define MGMT_CMD_COUNT 6
#define MGMT_MAX_STRING_LENGTH 0xFF

typedef char TString[MGMT_MAX_STRING_LENGTH];

typedef enum TMgmtCmd {
   MGMT_CMD_USERS = 0,
   MGMT_CMD_ADD_USER,
   MGMT_CMD_DELETE_USER,
   MGMT_CMD_GET_DISSECTOR,
   MGMT_CMD_SET_DISSECTOR,
   MGMT_CMD_STATISTICS
} TMgmtCmd;

typedef enum TMgmtState {
    MGMT_WAITING_CMD,
    MGMT_READING_ARGS,
    MGMT_END,
    MGMT_ERROR
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

    uint8_t readCommands;

    uint8_t slength;    // Lenght to read from a string arg
    uint8_t rlength;    // Already read bytes form a string
    TArg args[MGMT_CMD_COUNT+1];
} TMgmtParser;


void initMgmtCmdParser(TMgmtParser* p);
TMgmtState mgmtCmdParse(TMgmtParser* p, struct buffer* buffer);
bool hasMgmtCmdReadEnded(TMgmtParser* p);
bool hasMgmtCmdErrors(TMgmtParser* p);
uint8_t fillMgmtCmdAnswer(TMgmtParser* p, struct buffer* buffer);

#endif // MANAGEMENT_CMD_PARSER_H