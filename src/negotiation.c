#include "negotiation.h"
#include <stdio.h>
#include <stdlib.h>

typedef TNegState (*parseCharacter)(TNegParser* p, uint8_t c);

TNegState parseVersion(TNegParser* p, uint8_t c);
TNegState parseMethodCount(TNegParser* p, uint8_t c);
TNegState parseMethods(TNegParser* p, uint8_t c);
TNegState parseEnd(TNegParser* p, uint8_t c);

static parseCharacter stateRead[] = {
    /* VERSION      */ (parseCharacter)parseVersion,
    /* METHOD_COUNT */ (parseCharacter)parseMethodCount,
    /* METHODS      */ (parseCharacter)parseMethods,
    /* END          */ (parseCharacter)parseEnd,
    /* ERROR        */ (parseCharacter)parseEnd};

TNegState negotiationRead(TNegParser* p, uint8_t* buffer, int bufferSize) {
    for (int i = 0; i < bufferSize && p->state != NEG_ERROR && p->state != NEG_END; i++) {
        p->state = stateRead[p->state](p, buffer[i]);
    }
    return p->state;
}

TNegParser* newNegotiationParser() {
    TNegParser* p = calloc(sizeof(TNegParser), 1);
    p->state = NEG_VERSION;
    p->authMethod = NEG_METHOD_NO_MATCH;
    return p;
}

void freeNegotiationParser(TNegParser* p) {
    free(p);
}

TNegState parseVersion(TNegParser* p, uint8_t c) {
    if (c != 5) {
        printf("[ERR] Client specified invalid version: %d\n", c);
        return NEG_ERROR;
    }
    return NEG_METHOD_COUNT;
}

TNegState parseMethodCount(TNegParser* p, uint8_t c) {
    p->pendingMethods = c;
    if (c == 0) {
        printf("[INF] Client did not specify auth methods \n");
        return NEG_END;
    }
    printf("[INF] Client specified auth methods: ");
    return NEG_METHODS;
}

TNegState parseMethods(TNegParser* p, uint8_t c) {
    p->pendingMethods -= 1;
    printf("%x%s", c, p->pendingMethods == 0 ? "\n" : ", ");
    if (c == NEG_METHOD_NO_AUTH) {
        p->authMethod = NEG_METHOD_NO_AUTH;
    } else if (c == NEG_METHOD_PASS) {
        // wait until pass/user auth method is developed
    }
    return p->pendingMethods == 0 ? NEG_END : NEG_METHODS;
}

/*Should not happen*/
TNegState parseEnd(TNegParser* p, uint8_t c) {
    printf("[BUG] Trying to call negotiation parser in END/ERROR state ");
    return p->state;
}