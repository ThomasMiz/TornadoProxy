#ifndef REQUEST_H
#define REQUEST_H

#include "../selector.h"
#include "requestParser.h"

void requestReadInit(const unsigned state, TSelectorKey* key);
unsigned requestRead(TSelectorKey* key);

unsigned requestWrite(TSelectorKey* key);
unsigned requestResolveDone(TSelectorKey* key);
unsigned fillRequestAnswerWithState(TSelectorKey* key, int state);

#endif // NEGOTIATION_PARSER_H
