#include "negotiationParser.h"
#include <stdio.h>
#include <stdlib.h>

#define VERSION_5 0x05

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

TNegState negotiationParse(TNegParser* p, struct buffer* buffer) {
    while (buffer_can_read(buffer) && p->state != NEG_ERROR && p->state != NEG_END) {
        p->state = stateRead[p->state](p, buffer_read(buffer));
    }
    return p->state;
}

void initNegotiationParser(TNegParser* p) {
    if (p == NULL)
        return;
    p->state = NEG_VERSION;
    p->authMethod = NEG_METHOD_NO_MATCH;
}

uint8_t hasNegotiationReadEnded(TNegParser* p) {
    return p->state == NEG_END || p->state == NEG_ERROR;
}
uint8_t hasNegotiationErrors(TNegParser* p) {
    return p->state == NEG_ERROR;
}

uint8_t fillNegotiationAnswer(TNegParser* p, struct buffer* buffer) {
    if (!buffer_can_write(buffer))
        return 1;
    buffer_write(buffer, VERSION_5);
    if (!buffer_can_write(buffer))
        return 1;
    buffer_write(buffer, p->authMethod);
    return 0;
}

TNegState parseVersion(TNegParser* p, uint8_t c) {
    if (c != VERSION_5) {
        printf("[Neg parser: ERR] Client specified invalid version: %d\n", c);
        return NEG_ERROR;
    }
    return NEG_METHOD_COUNT;
}

TNegState parseMethodCount(TNegParser* p, uint8_t c) {
    p->pendingMethods = c;
    if (c == 0) {
        printf("[Neg parser: INF] Client did not specify auth methods \n");
        return NEG_END;
    }
    printf("[Neg parser: INF] Client specified auth methods: ");
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
    printf("[Neg parser: BUG] Trying to call negotiation parser in END/ERROR state ");
    return p->state;
}