#ifndef MGMT_AUTH_H
#define MGMT_AUTH_H

#include "selector.h"
void mgmtAuthReadInit(const unsigned state, TSelectorKey* key);
unsigned mgmtAuthRead(TSelectorKey* key);
unsigned mgmtAuthWrite(TSelectorKey* key);

#endif // MGMT_AUTH_H
