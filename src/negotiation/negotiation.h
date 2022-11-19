#ifndef NEGOTIATION_H
#define NEGOTIATION_H

#include "../selector.h"
#include "negotiationParser.h"

void negotiationReadInit(const unsigned state, TSelectorKey* key);
unsigned negotiationRead(TSelectorKey* key);
unsigned negotiationWrite(TSelectorKey* key);

#endif // NEGOTIATION_H
