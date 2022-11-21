#include "mgmtCmdParser.h"
#include "../logger.h"

#define MGMT_CMD_COUNT 10

typedef TMgmtState (*parseCharacter)(TMgmtParser* p, uint8_t c);

typedef enum ARG_TYPE{
    STRING = 0,
    BYTE,
    EMPTY,
}ARG_TYPE;

typedef struct TCmd{
    TMgmtCmd id;
    uint8_t argc;
    ARG_TYPE argt[MGMT_MAX_ARGS];
}TCmd;

static TCmd commands[] = {
        {       .id = MGMT_CMD_USERS,
                .argc = 0,
                // NO ARGS -> NO ARG TYPE
                },
        {
                .id = MGMT_CMD_ADD_USER,
                .argc = 3,
                .argt = {STRING, STRING, BYTE},
        },
        {
                .id = MGMT_CMD_DELETE_USER,
                .argc = 1,
                .argt = {STRING, EMPTY, EMPTY},
        },
        {
                .id = MGMT_CMD_CHANGE_PASSWORD,
                .argc = 1,
                .argt = {STRING, EMPTY, EMPTY},
        },
        {
                .id = MGMT_CHANGE_ROLE,
                .argc = 1,
                .argt = {STRING, EMPTY, EMPTY},
        },
        {       .id = MGMT_CMD_GET_DISSECTOR,
                .argc = 0,
        },
        {
                .id = MGMT_CMD_SET_DISSECTOR,
                .argc = 1,
                .argt = {BYTE,EMPTY, EMPTY},
        },
        {       .id = MGMT_CMD_GET_AUTHENTICATION_STATUS,
                .argc = 0,
        },
        {
                .id = MGMT_CMD_SET_AUTHENTICATION_STATUS,
                .argc = 1,
                .argt = {BYTE, EMPTY, EMPTY},
        },
        {
                .id = MGMT_CMD_STATISTICS,
                .argc = 0,
                // NO ARGS -> NO ARG TYPE
        },
};

static TMgmtState parseCmd(TMgmtParser* p, uint8_t c);
static TMgmtState parseArgs(TMgmtParser* p, uint8_t c);
static TMgmtState parseEnd(TMgmtParser* p, uint8_t c);


static parseCharacter stateRead[] = {
        /* MGMTP_WAITING_CMD    */ parseCmd,
        /* MGMTP_READING_ARGS   */ parseArgs,
        /* MGMTP_END            */ parseEnd,
        /* MGMTP_ERROR          */ parseEnd};


void initMgmtCmdParser(TMgmtParser* p){
    if(p==NULL)
        return;
    p->state = MGMTP_WAITING_CMD;
    p->readArgs = 0;
    p->slength = 0;
    p->rlength = 0;
}
TMgmtState mgmtCmdParse(TMgmtParser* p, struct buffer* buffer){
    while (buffer_can_read(buffer) && !hasMgmtCmdReadEnded(p)) {
        p->state = stateRead[p->state](p, buffer_read(buffer));
    }
    return p->state;
}
bool hasMgmtCmdReadEnded(TMgmtParser* p){
    return p->state == MGMTP_END || p->state ==MGMTP_ERROR;
}
bool hasMgmtCmdErrors(TMgmtParser* p){
    return p->state ==MGMTP_ERROR;
}
uint8_t fillMgmtCmdAnswer(TMgmtParser* p, struct buffer* buffer){
    buffer_write(buffer, p->cmd + '0');
    return 0;
}

/*Should not happen*/
static TMgmtState parseEnd(TMgmtParser* p, uint8_t c) {
    log(LOG_ERROR, "Trying to call negotiation parser in END/ERROR state with char: %c", c);
    return p->state;
}

static TMgmtState parseCmd(TMgmtParser* p, uint8_t c){
    if(c>=MGMT_CMD_COUNT){
        p->status = MGMT_INVALID_CMD;
        return MGMTP_ERROR;
    }
    p->cmd = c;
    return commands[c].argc == 0 ? MGMTP_END : MGMTP_READING_ARGS;
}
static TMgmtState parseArgs(TMgmtParser* p, uint8_t c){
    ARG_TYPE at = commands[p->cmd].argt[p->readArgs];

    if(at == STRING){
        //Reading string length
        if(p->slength == 0){
            // Strings can not have a length of 0
            if(c == 0){
                p->status = MGMT_INVALID_CMD;
                return MGMTP_ERROR;
            }
            p->slength = c;
            return MGMTP_READING_ARGS;
        }

        //Reading string
        p->args[p->readArgs].string[p->rlength++]=c;

        //Check if the string ended
        if(p->slength == p->rlength){
            p->args[p->readArgs].string[p->rlength]=0;
            p->readArgs++;
            log(DEBUG, "String arg read: %s, read commands: %d", p->args[p->readArgs-1].string, p->readArgs);
            if(p->readArgs == commands[p->cmd].argc){
                return MGMTP_END;
            }
            //restart counters in case another string comes
            p->slength = p->rlength = 0;
        }
        return MGMTP_READING_ARGS;
    }

    if(at == BYTE){
        log(DEBUG, "Byte arg read: %d", c);
        p->args[p->readArgs++].byte = c;
        return p->readArgs == commands[p->cmd].argc ? MGMTP_END : MGMTP_READING_ARGS;
    }

    // at == EMPTY
    log(LOG_ERROR, "Trying to parse empty arg, cmd: %d", p->cmd);
    return MGMTP_ERROR;
}