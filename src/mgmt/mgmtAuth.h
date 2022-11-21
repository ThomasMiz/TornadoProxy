#ifndef MGMT_AUTH_H
#define MGMT_AUTH_H

#include "../selector.h"

/**
 * @brief Handler to initialize resources when the MGMT_AUTH_READ state is reached
 *
 * @param state the state from which the state machine arrived
 * @param key Selector key that holds information regarding the woken up fd
 */
void mgmtAuthReadInit(const unsigned state, TSelectorKey* key);

/**
 * @brief Handler to read from ready file descriptor inside MGMT_AUTH_READ state
 * @param state the state from which the state machine arrived
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned mgmtAuthRead(TSelectorKey* key);

/**
 * @brief Handler to write to ready file descriptor inside MGMT_AUTH_WRITE state
 * @param state the state from which the state machine arrived
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned mgmtAuthWrite(TSelectorKey* key);

#endif // MGMT_AUTH_H
