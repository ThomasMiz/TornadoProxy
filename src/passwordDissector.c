// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "passwordDissector.h"
#include "logging/logger.h"
#include <stdio.h>

#define CLIENT_IDX 0
#define ORIGIN_IDX 1

#define TO_LOWER(x) ((x) | 0x20)

typedef TPDStatus (*parseCharacter)(TPDissector* p, uint8_t c);

static TPDStatus readPlus(TPDissector* p, uint8_t c);
static TPDStatus turnOff(TPDissector* p, uint8_t c);
static TPDStatus doNothing(TPDissector* p, uint8_t c);

static TPDStatus readU(TPDissector* p, uint8_t c);
static TPDStatus readS0(TPDissector* p, uint8_t c);
static TPDStatus readE(TPDissector* p, uint8_t c);
static TPDStatus readR(TPDissector* p, uint8_t c);
static TPDStatus readUW(TPDissector* p, uint8_t c);

static TPDStatus readUser(TPDissector* p, uint8_t c);

// VU stands for "valid user"
static TPDStatus readPlusVU(TPDissector* p, uint8_t c);

static TPDStatus readP(TPDissector* p, uint8_t c);
static TPDStatus readA(TPDissector* p, uint8_t c);
static TPDStatus readS1(TPDissector* p, uint8_t c);
static TPDStatus readS2(TPDissector* p, uint8_t c);
static TPDStatus readPW(TPDissector* p, uint8_t c);
static TPDStatus readPass(TPDissector* p, uint8_t c);

static TPDStatus readPlusFinal(TPDissector* p, uint8_t c);

static parseCharacter stateRead[][2] = {/* CLIENT     -   ORIGIN */
                                        /* PDS_SERVER_PLUS          */ {turnOff, readPlus},

                                        /* PDS_USER_U               */ {readU, doNothing},
                                        /* PDS_USER_S               */ {readS0, doNothing},
                                        /* PDS_USER_E               */ {readE, doNothing},
                                        /* PDS_USER_R               */ {readR, doNothing},
                                        /* PDS_USER_R               */ {readUW, doNothing},
                                        /* PDS_READING_USER         */ {readUser, doNothing},

                                        /* PDS_PASS_P               */ {readP, readPlusVU},
                                        /* PDS_PASS_A               */ {readA, readPlusVU},
                                        /* PDS_PASS_S               */ {readS1, readPlusVU},
                                        /* PDS_PASS_S2              */ {readS2, readPlusVU},
                                        /* PDS_PASS_S2              */ {readPW, readPlusVU},
                                        /* PDS_READING_PASS         */ {readPass, readPlusVU},

                                        /* PDS_CHECK                */ {doNothing, readPlusFinal},

                                        /* PDS_END                  */ {doNothing, doNothing}};

static bool isDissectorOn = true;

void turnOffPDissector() {
    isDissectorOn = false;
}
void turnOnPDissector() {
    isDissectorOn = true;
}

bool isPDissectorOn() {
    return isDissectorOn;
}

void initPDissector(TPDissector* pd, in_port_t port, int clientFd, int originFd) {
    if (pd == NULL) {
        return;
    }
    if (port != POP3_DEFAULT_PORT) {
        pd->isOn = false;
        return;
    }
    pd->state = PDS_SERVER_PLUS;
    pd->writeIdx = 0;
    pd->isOn = isDissectorOn;
    pd->validUsername = false;
    pd->clientFd = clientFd;
    pd->originFd = originFd;
}

TPDStatus parseUserData(TPDissector* pd, struct buffer* buffer, int fd) {
    int idx = (fd == pd->clientFd ? CLIENT_IDX : ORIGIN_IDX);
    int end = buffer->write - buffer->read;
    for (int i = 0; i < end && pd->state != PDS_END; ++i) {
        pd->state = stateRead[pd->state][idx](pd, buffer->read[i]);
    }

    if (pd->state == PDS_END) {
        pd->isOn = false;
        logf(LOG_DEBUG, "passwordDissector parseUserData: username: [%s] - password: [%s]", pd->username, pd->password);
    }
    return pd->state;
}

static TPDStatus readPlus(TPDissector* p, uint8_t c) {
    if (c == '+') {
        return PDS_USER_U;
    }
    p->isOn = false;
    return PDS_END;
}
static TPDStatus turnOff(TPDissector* p, uint8_t c) {
    p->isOn = false;
    return PDS_END;
}

static TPDStatus doNothing(TPDissector* p, uint8_t c) {
    return p->state;
}

static TPDStatus readU(TPDissector* p, uint8_t c) {
    return TO_LOWER(c) == 'u' ? PDS_USER_S : PDS_USER_U;
}

static TPDStatus readS0(TPDissector* p, uint8_t c) {
    return TO_LOWER(c) == 's' ? PDS_USER_E : PDS_USER_U;
}

static TPDStatus readE(TPDissector* p, uint8_t c) {
    return TO_LOWER(c) == 'e' ? PDS_USER_R : PDS_USER_U;
}

static TPDStatus readR(TPDissector* p, uint8_t c) {
    return TO_LOWER(c) == 'r' ? PDS_USER_W : PDS_USER_U;
}

static TPDStatus readUW(TPDissector* p, uint8_t c) {
    return c == ' ' ? PDS_READING_USER : PDS_USER_U;
}

static TPDStatus readUser(TPDissector* p, uint8_t c) {
    if (c == '\n' || p->writeIdx >= PDS_MAX_USER_LENGTH) {
        p->username[p->writeIdx] = 0;
        p->writeIdx = 0;
        return PDS_PASS_P;
    }
    if (c != '\r') {
        p->username[p->writeIdx++] = c;
    }
    return PDS_READING_USER;
}

static TPDStatus readPlusVU(TPDissector* p, uint8_t c) {
    if (c == '-') {
        p->validUsername = false;
        return PDS_USER_U;
    }
    if (c == '+') {
        p->validUsername = true;
    }
    return p->state;
}

static TPDStatus readP(TPDissector* p, uint8_t c) {
    if (TO_LOWER(c) == 'u') {
        return PDS_USER_S;
    }
    return TO_LOWER(c) == 'p' ? PDS_PASS_A : PDS_USER_U;
}

static TPDStatus readA(TPDissector* p, uint8_t c) {
    return TO_LOWER(c) == 'a' ? PDS_PASS_S : PDS_USER_U;
}

static TPDStatus readS1(TPDissector* p, uint8_t c) {
    return TO_LOWER(c) == 's' ? PDS_PASS_S2 : PDS_USER_U;
}

static TPDStatus readS2(TPDissector* p, uint8_t c) {
    return TO_LOWER(c) == 's' ? PDS_PASS_W : PDS_USER_U;
}

static TPDStatus readPW(TPDissector* p, uint8_t c) {
    return c == ' ' ? PDS_READING_PASS : PDS_USER_U;
}

static TPDStatus readPass(TPDissector* p, uint8_t c) {
    if (c == '\n' || p->writeIdx >= PDS_MAX_PASS_LENGTH) {
        p->password[p->writeIdx] = 0;
        p->writeIdx = 0;
        return PDS_CHECK;
    }
    if (c != '\r') {
        p->password[p->writeIdx++] = c;
    }
    return PDS_READING_PASS;
}

static TPDStatus readPlusFinal(TPDissector* p, uint8_t c) {
    if (c == '-') {
        p->validUsername = false;
        return PDS_USER_U;
    }
    if (c == '+') {
        // Valid user/pass found
        if (p->validUsername) {
            logf(LOG_INFO, "POP3 credentials intercepted on client %d: username=\"%s\", password=\"%s\"", p->clientFd, p->username, p->password);
            return PDS_END;
        }
        // user sended user and pass first, then server answers.
        p->validUsername = true;
    }
    return p->state;
}