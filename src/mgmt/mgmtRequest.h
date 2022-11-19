#ifndef MANAGEMENT_REQUEST_H
#define MANAGEMENT_REQUEST_H


#include "../selector.h"
void mgmtRequestReadInit(const unsigned state, TSelectorKey* key);
unsigned mgmtRequestRead(TSelectorKey* key);
unsigned mgmtRequestWrite(TSelectorKey* key);


#endif // MANAGEMENT_REQUEST_H