#include "passwordDissector.h"
#include "logger.h"
#include <stdio.h>

#define CLIENT_IDX 0
#define ORIGIN_IDX 1

#define TO_LOWER(x) ((x)|0x20)

typedef TPDStatus (*parseCharacter)(TPDissector* p, uint8_t c);

static TPDStatus readPlus(TPDissector* p, uint8_t c);
static TPDStatus turnOff(TPDissector* p, uint8_t c);
static TPDStatus doNothing(TPDissector* p, uint8_t c);

static TPDStatus readU(TPDissector* p, uint8_t c);
static TPDStatus readS0(TPDissector* p, uint8_t c);
static TPDStatus readE(TPDissector* p, uint8_t c);
static TPDStatus readR(TPDissector* p, uint8_t c);

static TPDStatus readUser(TPDissector* p, uint8_t c);

static TPDStatus readP(TPDissector* p, uint8_t c);
static TPDStatus readA(TPDissector* p, uint8_t c);
static TPDStatus readS1(TPDissector* p, uint8_t c);
static TPDStatus readS2(TPDissector* p, uint8_t c);
static TPDStatus readPass(TPDissector* p, uint8_t c);

static parseCharacter stateRead[][2] = { /* CLIENT     -   ORIGIN */
        /* PDS_SERVER_PLUS          */{turnOff, readPlus},

        /* PDS_USER_U               */{readU, doNothing},
        /* PDS_USER_S               */{readS0, doNothing},
        /* PDS_USER_E               */{readE, doNothing},
        /* PDS_USER_R               */{readR, doNothing},
        /* PDS_READING_USER         */{readUser, doNothing},

        /* PDS_PASS_P               */{readP,doNothing},
        /* PDS_PASS_A               */{readA,doNothing},
        /* PDS_PASS_S               */{readS1,doNothing},
        /* PDS_PASS_S2              */{readS2,doNothing},
        /* PDS_READING_PASS         */{readPass,doNothing},

        // TODO: Check server answer

        /* PDS_END                  */{doNothing, doNothing}};

static bool isDissectorOn = true;

void turnOffPDissector(){
    isDissectorOn = true;
}
void turnOnPDissector(){
    isDissectorOn = false;
}

void initPDissector(TPDissector * pd, in_port_t port, int clientFd, int originFd){
    if(pd == NULL){
        return;
    }
    if(port != POP3_DEFAULT_PORT){
        pd->isOn = false;
        return;
    }
    pd->state = PDS_SERVER_PLUS;
    pd->writeIdx = 0;
    pd->isOn = true;
    pd->clientFd = clientFd;
    pd->originFd = originFd;
}

TPDStatus parseUserData(TPDissector * pd, struct buffer * buffer, int fd) {
    int idx = (fd == pd->clientFd ? CLIENT_IDX : ORIGIN_IDX);
    int end = buffer->write - buffer->read;
    for(int i = 0; i<end && pd->state != PDS_END ; ++i) {
        pd->state = stateRead[pd->state][idx](pd, buffer->read[i]);
    }

    //TODO: remove and check where to log
    if(pd->state == PDS_END){
        printf("username: [%s] - password: [%s]", pd->username, pd->password);
    }
    return pd->state;
}

static TPDStatus readPlus(TPDissector* p, uint8_t c){
    if(c=='+'){
        return PDS_USER_U;
    }
    p->isOn = false;
    return PDS_END;
}
static TPDStatus turnOff(TPDissector* p, uint8_t c){
    p->isOn = false;
    return PDS_END;
}

static TPDStatus doNothing(TPDissector* p, uint8_t c){
    return p->state;
}



static TPDStatus readU(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 'u' ? PDS_USER_S : PDS_USER_U;
}

static TPDStatus readS0(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 's' ? PDS_USER_E : PDS_USER_U;
}

static TPDStatus readE(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 'e' ? PDS_USER_R : PDS_USER_U;
}

static TPDStatus readR(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 'r' ? PDS_READING_USER : PDS_USER_U;
}

static TPDStatus readUser(TPDissector* p, uint8_t c){
    if(c=='\n' || p->writeIdx >= PDS_MAX_USER_LENGTH){
        p->username[p->writeIdx] = 0;
        p->writeIdx = 0;
        return PDS_PASS_P;
    }
    if(c !='\r'){
        p->username[p->writeIdx++] = c;
    }
    return PDS_READING_USER;
}




static TPDStatus readP(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 'p' ? PDS_PASS_A : PDS_PASS_P;
}

static TPDStatus readA(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 'a' ? PDS_PASS_S : PDS_PASS_P;
}

static TPDStatus readS1(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 's' ? PDS_PASS_S2 : PDS_PASS_P;
}

static TPDStatus readS2(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 's' ? PDS_READING_PASS : PDS_PASS_P;
}

static TPDStatus readPass(TPDissector* p, uint8_t c){
    if(c=='\n' || p->writeIdx >= PDS_MAX_PASS_LENGTH){
        p->username[p->writeIdx] = 0;
        p->writeIdx = 0;
        return PDS_END;
    }
    if(c!='\r'){
        p->password[p->writeIdx++] = c;
    }
    return PDS_READING_PASS;
}