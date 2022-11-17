
#ifndef COPY_H
#define COPY_H
#include "selector.h"
#include "buffer.h"


typedef struct TCopy{
    buffer * otherBuffer;
    buffer * targetBUffer;
    int * targetFd;
    int * otherFd;
    TSelector s;
    char * name;
    size_t duplex;
    size_t * otherDuplex;
    struct TCopy * otherCopy;
}TCopy;

typedef struct TConnection{
    TCopy clientCopy;
    TCopy originCopy;
}TConnection;


void socksv5HandleInit(const unsigned int st, TSelectorKey* key);
unsigned socksv5HandleRead(TSelectorKey* key);
unsigned socksv5HandleWrite(TSelectorKey* key);
void socksv5HandleClose(const unsigned int state, TSelectorKey* key);

#endif
