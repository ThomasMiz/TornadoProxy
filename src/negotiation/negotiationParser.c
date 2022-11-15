#include "negotiationParser.h"
#include "../logger.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define VERSION_5 0x05

typedef TNegState (*parseCharacter)(TNegParser* p, uint8_t c);

static TNegState parseVersion(TNegParser* p, uint8_t c);
static TNegState parseMethodCount(TNegParser* p, uint8_t c);
static TNegState parseMethods(TNegParser* p, uint8_t c);
static TNegState parseEnd(TNegParser* p, uint8_t c);

static uint8_t requiredAuthMethod = NEG_METHOD_PASS;

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

static TNegState parseVersion(TNegParser* p, uint8_t c) {
    if (c != VERSION_5) {
        log(INFO, "Client specified invalid version: %d\n", c);
        return NEG_ERROR;
    }
    return NEG_METHOD_COUNT;
}

static TNegState parseMethodCount(TNegParser* p, uint8_t c) {
    p->pendingMethods = c;
    if (c == 0) {
        return NEG_END;
    }
    log(INFO, "Client specified %d auth methods: ", c);
    return NEG_METHODS;
}

static TNegState parseMethods(TNegParser* p, uint8_t c) {
    p->pendingMethods -= 1;
    log(INFO, "%x%s", c, p->pendingMethods == 0 ? " " : ", ");
    if (c == requiredAuthMethod) {
        p->authMethod = requiredAuthMethod;
    }
    return p->pendingMethods == 0 ? NEG_END : NEG_METHODS;
}

/*Should not happen*/
static TNegState parseEnd(TNegParser* p, uint8_t c) {
    log(LOG_ERROR, "Trying to call negotiation parser in END/ERROR state with char: %c", c);
    return p->state;
}

uint8_t changeAuthMethod(TNegParser* p, TNegMethod authMethod) {
    if (authMethod == NEG_METHOD_PASS || authMethod == NEG_METHOD_NO_AUTH) {
        requiredAuthMethod = authMethod;
        return 0;
    }
    return 1;
}
