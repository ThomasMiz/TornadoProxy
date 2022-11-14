#ifndef AUTH_H
#define AUTH_H

#include "../selector.h"
#include "authParser.h"

void authReadInit(const unsigned state, TSelectorKey* key);
unsigned authRead(TSelectorKey* key);
unsigned authWrite(TSelectorKey* key);

#endif // AUTH_H
