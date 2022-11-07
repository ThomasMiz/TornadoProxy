#ifndef REQUEST_H
#define REQUEST_H

#include "requestParser.h"
#include "selector.h"

void requestReadInit(const unsigned state, TSelectorKey* key);
unsigned requestRead(TSelectorKey* key);

unsigned requestWrite(TSelectorKey* key);

#endif // NEGOTIATION_PARSER_H