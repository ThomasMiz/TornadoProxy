#include "negotiation.h"
#include <stdio.h>
#include <stdlib.h>

typedef negState (*parseCharacter)(negParser* p, uint8_t c);

negState parseVersion(negParser* p, uint8_t c);
negState parseMethodCount(negParser* p, uint8_t c);
negState parseMethods(negParser* p, uint8_t c);
negState parseEnd(negParser* p, uint8_t c);
negState parseError(negParser* p, uint8_t c);

static parseCharacter stateRead[] = {
    /* VERSION      */ (parseCharacter)parseVersion,
    /* METHOD_COUNT */ (parseCharacter)parseMethodCount,
    /* METHODS      */ (parseCharacter)parseMethods,
    /* END          */ (parseCharacter)parseEnd,
    /* ERROR        */ (parseCharacter)parseError,
};

negState negotiationRead(negParser* p, uint8_t* buffer, int bufferSize) {
    negState state = p->state;
    for (int i = 0; i < bufferSize && state != ERROR && state != END; i++) {
        state = stateRead[state](p, buffer[i]);
    }
    return p->state = state;
}

negParser* newNegotiationParser() {
    negParser* p = calloc(sizeof(negParser), 1);
    p->state = VERSION;
    p->authMethod = NEGOTIATION_METHOD_NO_MATCH;
    return p;
}

void freeNegotiationParser(negParser* p) {
    free(p);
}

negState parseVersion(negParser* p, uint8_t c) {
    if (c != 5) {
        printf("[ERR] Client specified invalid version: %d\n", c);
        return ERROR;
    }
    return METHOD_COUNT;
}

negState parseMethodCount(negParser* p, uint8_t c) {
    p->pendingMethods = c;
    if (c == 0) {
        printf("[INF] Client did not specify auth methods \n");
        return END;
    }
    printf("[INF] Client specified auth methods: ");
    return METHODS;
}

negState parseMethods(negParser* p, uint8_t c) {
    p->pendingMethods -= 1;
    printf("%x%s", c, p->pendingMethods == 0 ? "\n" : ", ");
    if (c == NEGOTIATION_METHOD_NO_AUTH) {
        p->authMethod = NEGOTIATION_METHOD_NO_AUTH;
    } else if (c == NEGOTIATION_METHOD_PASS) {
        // wait until pass/user auth method is developed
    }
    return p->pendingMethods == 0 ? END : METHODS;
}

/*Should not happen*/
negState parseEnd(negParser* p, uint8_t c) {
    printf("[BUG] Trying to call negotiation parser in END state ");
    return END;
}

/*Should not happen*/
negState parseError(negParser* p, uint8_t c) {
    printf("[BUG] Trying to call negotiation parser in ERROR state ");
    return ERROR;
}
