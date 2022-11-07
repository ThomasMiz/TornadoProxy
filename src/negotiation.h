#ifndef NEGOTIATION_H
#define NEGOTIATION_H

#include "negotiationParser.h"
#include "selector.h"

void negotiationReadInit(const unsigned state, TSelectorKey* key);
unsigned negotiationRead(TSelectorKey* key);

unsigned negotiationWrite(TSelectorKey* key);

#endif // NEGOTIATION_PARSER_H