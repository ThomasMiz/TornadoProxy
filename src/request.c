#include "request.h"
#include <stdio.h>
#include <stdlib.h>

typedef TReqState (*parseCharacter)(TReqParser* p, uint8_t c);

static TReqState reqParseEnd(TReqParser* p, uint8_t c);
static TReqState reqParseVersion(TReqParser* p, uint8_t c);
static TReqState reqParseCmd(TReqParser* p, uint8_t c);
static TReqState reqParseRsv(TReqParser* p, uint8_t c);
static TReqState reqParseAtyp(TReqParser* p, uint8_t c);
static TReqState reqParseDnLength(TReqParser* p, uint8_t c);
static TReqState reqParseDstAddr(TReqParser* p, uint8_t c);
static TReqState reqParseDstPort(TReqParser* p, uint8_t c);

static parseCharacter stateRead[] = {
    /* REQ_SUCCEDED                         */ (parseCharacter)reqParseEnd,
    /* REQ_ERROR_GENERAL_FAILURE            */ (parseCharacter)reqParseEnd,
    /* REQ_ERROR_CONNECTION_NOT_ALLOWED     */ (parseCharacter)reqParseEnd,
    /* REQ_ERROR_NTW_UNREACHABLE            */ (parseCharacter)reqParseEnd,
    /* REQ_ERROR_HOST_UNREACHABLE           */ (parseCharacter)reqParseEnd,
    /* REQ_ERROR_CONNECTION_REFUSED         */ (parseCharacter)reqParseEnd,
    /* REQ_ERROR_TTL_EXPIRED                */ (parseCharacter)reqParseEnd,
    /* REQ_ERROR_COMMAND_NOT_SUPPORTED      */ (parseCharacter)reqParseEnd,
    /* REQ_ERROR_ADDRESS_TYPE_NOT_SUPPORTED */ (parseCharacter)reqParseEnd,
    /* REQ_VERSION                          */ (parseCharacter)reqParseVersion,
    /* REQ_CMD                              */ (parseCharacter)reqParseCmd,
    /* REQ_RSV                              */ (parseCharacter)reqParseRsv,
    /* REQ_ATYP                             */ (parseCharacter)reqParseAtyp,
    /* REQ_DN_LENGHT                        */ (parseCharacter)reqParseDnLength,
    /* REQ_DST_ADDR                         */ (parseCharacter)reqParseDstAddr,
    /* REQ_DST_PORT                         */ (parseCharacter)reqParseDstPort};

static uint8_t isErrorState(TReqState state) {
    return state >= REQ_ERROR_GENERAL_FAILURE && state <= REQ_ERROR_ADDRESS_TYPE_NOT_SUPPORTED;
}

void initRequestParser(TReqParser* p) {
    if (p == NULL)
        return;
    p->state = REQ_VERSION;
    p->readBytes = 0;
    p->port = 0;
}
TReqState requestRead(TReqParser* p, uint8_t* buffer, int bufferSize) {
    for (int i = 0; i < bufferSize && p->state != REQ_SUCCEDED && !isErrorState(p->state); i++) {
        p->state = stateRead[p->state](p, buffer[i]);
    }
    return p->state;
}

uint8_t hasReadEnded(TReqParser* p) {
    p->state == REQ_SUCCEDED;
}
uint8_t hasErrors(TReqParser* p) {
    p->state == isErrorState(p->state);
}

/*Should not happen*/
static TReqState reqParseEnd(TReqParser* p, uint8_t c) {
    fprintf(stderr, "[BUG] Trying to call negotiation parser in SUCCED/ERROR state ");
    return p->state;
}

static TReqState reqParseVersion(TReqParser* p, uint8_t c) {
    if (c != 5) {
        fprintf(stderr, "[ERR] Client specified invalid version: 0x%d\n", c);
        return REQ_ERROR_GENERAL_FAILURE;
    }
    return REQ_CMD;
}

static TReqState reqParseCmd(TReqParser* p, uint8_t c) {
    if (c == REQ_CMD_CONNECT) {
        return REQ_RSV;
    }
    fprintf(stderr, "[ERR] Client specified invalid CMD: 0x%d\n", c);
    return REQ_ERROR_COMMAND_NOT_SUPPORTED;
}
static TReqState reqParseRsv(TReqParser* p, uint8_t c) {
    if (c == 0x00)
        return REQ_ATYP;
    fprintf(stderr, "[ERR] Client specified invalid number in rsv: 0x%d\n", c);
    return REQ_ERROR_GENERAL_FAILURE;
}
static TReqState reqParseAtyp(TReqParser* p, uint8_t c) {
    p->atyp = c;
    if (c == REQ_ATYP_IPV4) {
        p->totalAtypBytes = sizeof(p->address.ipv4);
        return REQ_DST_ADDR;
    } else if (c == REQ_ATYP_IPV6) {
        p->totalAtypBytes = sizeof(p->address.ipv6);
        return REQ_DST_ADDR;
    } else if (c == REQ_ATYP_DOMAINNAME) {
        return REQ_DN_LENGHT;
    }
    fprintf(stderr, "[ERR] Client specified an invalid ATYP: 0x%d\n", c);
    return REQ_ERROR_ADDRESS_TYPE_NOT_SUPPORTED;
}

static TReqState reqParseDnLength(TReqParser* p, uint8_t c) {
    p->totalAtypBytes = c;
    return REQ_DST_ADDR;
}

static TReqState reqParseDstAddr(TReqParser* p, uint8_t c) {
    p->address.bytes[p->readBytes++] = c;
    if (p->totalAtypBytes == p->readBytes) {
        p->readBytes = 0;
        return REQ_DST_PORT;
    }
    return REQ_DST_ADDR;
}
static TReqState reqParseDstPort(TReqParser* p, uint8_t c) {
    p->port = (p->port << 8) + c;
    return ++p->readBytes == PORT_BYTE_LENGHT ? REQ_SUCCEDED : REQ_DST_PORT;
}