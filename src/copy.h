
#ifndef COPY_H
#define COPY_H
#include "buffer.h"
#include "selector.h"

typedef struct TCopy {
    buffer* otherBuffer;
    buffer* targetBUffer;
    int* targetFd;
    int* otherFd;
    TSelector s;
    char* name;
    size_t duplex;
    size_t* otherDuplex;
    struct TCopy* otherCopy;
} TCopy;

typedef struct TConnection {
    TCopy clientCopy;
    TCopy originCopy;
} TConnection;

/**
 * @brief Handler to initialize resources when the COPY state is reached
 *
 * @param state the state from which the state machine arrived
 * @param key Selector key that holds information regarding the woken up fd
 */
void socksv5HandleInit(const unsigned int st, TSelectorKey* key);

/**
 * @brief Handler to read from ready file descriptor when inside COPY state
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned socksv5HandleRead(TSelectorKey* key);

/**
 * @brief Handler to write to ready file descriptor when inside COPY state
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned socksv5HandleWrite(TSelectorKey* key);

/**
 * @brief Handler to close resources when leaving COPY state
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
void socksv5HandleClose(const unsigned int state, TSelectorKey* key);

#endif
