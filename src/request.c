#include "request.h"
#include <stdio.h>
#include <stdlib.h>

typedef reqState (*parseCharacter)(reqParser* p, uint8_t c);

reqState reqParseEnd(reqParser* p, uint8_t c);
reqState reqParseVersion(reqParser* p, uint8_t c);
reqState reqParseCmd(reqParser* p, uint8_t c);
reqState reqParseRsv(reqParser* p, uint8_t c);
reqState reqParseAtyp(reqParser* p, uint8_t c);
reqState reqParseDnLength(reqParser* p, uint8_t c);
reqState reqParseDstAddr(reqParser* p, uint8_t c);
reqState reqParseDstPort(reqParser* p, uint8_t c);

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

uint8_t isErrorState(reqState state) {
    return state >= REQ_ERROR_GENERAL_FAILURE && state <= REQ_ERROR_ADDRESS_TYPE_NOT_SUPPORTED;
}

reqParser* newRequestParser() {
    reqParser* p = malloc(sizeof(reqParser));
    p->state = REQ_VERSION;
    p->readBytes = 0;
    p->port = 0;
    return p;
}
reqState requestRead(reqParser* p, uint8_t* buffer, int bufferSize) {
    for (int i = 0; i < bufferSize && p->state != REQ_SUCCEDED && !isErrorState(p->state); i++) {
        p->state = stateRead[p->state](p, buffer[i]);
    }
    return p->state;
}

void freeRequestParser(reqParser* p) {
    if (p != NULL) {
        free(p);
        if (p->atyp == REQ_ATYP_DOMAINNAME)
            free(p->address.domainname);
    }
}

/*Should not happen*/
reqState reqParseEnd(reqParser* p, uint8_t c) {
    fprintf(stderr, "[BUG] Trying to call negotiation parser in SUCCED/ERROR state ");
    return p->state;
}

reqState reqParseVersion(reqParser* p, uint8_t c) {
    if (c != 5) {
        fprintf(stderr, "[ERR] Client specified invalid version: 0x%d\n", c);
        return REQ_ERROR_GENERAL_FAILURE;
    }
    return REQ_CMD;
}

reqState reqParseCmd(reqParser* p, uint8_t c) {
    if (c == REQ_CMD_CONNECT) {
        return REQ_RSV;
    }
    fprintf(stderr, "[ERR] Client specified invalid CMD: 0x%d\n", c);
    return REQ_ERROR_COMMAND_NOT_SUPPORTED;
}
reqState reqParseRsv(reqParser* p, uint8_t c) {
    if (c == 0x00)
        return REQ_ATYP;
    fprintf(stderr, "[ERR] Client specified invalid number in rsv: 0x%d\n", c);
    return REQ_ERROR_GENERAL_FAILURE;
}
reqState reqParseAtyp(reqParser* p, uint8_t c) {
    if (c == REQ_ATYP_IPV4) {
        printf("[INF] Client specified an IPV4 address\n");
        p->atyp = REQ_ATYP_IPV4;
        p->totalAtypBytes = IPV4_BYTE_LENGHT;
        return REQ_DST_ADDR;
    } else if (c == REQ_ATYP_IPV6) {
        printf("[INF] Client specified an IPV6 address\n");
        p->atyp = REQ_ATYP_IPV6;
        p->totalAtypBytes = IPV6_BYTE_LENGHT;
        return REQ_DST_ADDR;
    } else if (c == REQ_ATYP_DOMAINNAME) {
        printf("[INF] Client specified a domainname address\n");
        p->atyp = REQ_ATYP_DOMAINNAME;
        return REQ_DN_LENGHT;
    }
    fprintf(stderr, "[ERR] Client specified an invalid ATYP: 0x%d\n", c);
    return REQ_ERROR_ADDRESS_TYPE_NOT_SUPPORTED;
}

reqState reqParseDnLength(reqParser* p, uint8_t c) {
    p->totalAtypBytes = c;
    p->address.domainname = malloc(c + 1);
    return REQ_DST_ADDR;
}

reqState reqParseDstAddr(reqParser* p, uint8_t c) {

    if (p->atyp == REQ_ATYP_DOMAINNAME) {
        p->address.domainname[p->readBytes++] = c;
    } else {
        p->address.ipv6[p->readBytes++] = c;
    }

    if (p->totalAtypBytes == p->readBytes) {
        p->readBytes = 0;
        return REQ_DST_PORT;
    }

    return REQ_DST_ADDR;
}
reqState reqParseDstPort(reqParser* p, uint8_t c) {
    p->port = (p->port << 8) + c;
    return ++p->readBytes == PORT_BYTE_LENGHT ? REQ_SUCCEDED : REQ_DST_PORT;
}