#ifndef MANAGEMENT_REQUEST_H
#define MANAGEMENT_REQUEST_H

#include "../selector.h"


/**
 * @brief Handler to initialize resources when the MGMT_REQUEST_READ state is reached
 *
 * @param state the state from which the state machine arrived
 * @param key Selector key that holds information regarding the woken up fd
 */
void mgmtRequestReadInit(const unsigned state, TSelectorKey* key);

/**
 * @brief Handler to read from ready file descriptor when inside MGMT_REQUEST_READ state
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned mgmtRequestRead(TSelectorKey* key);

/**
 * @brief Handler to write to ready file descriptor when inside MGMT_REQUEST_WRITE state
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned mgmtRequestWrite(TSelectorKey* key);

/**
 * @brief Handler to initialize resources when the MGMT_REQUEST_WRITE state is reached
 *
 * @param state the state from which the state machine arrived
 * @param key Selector key that holds information regarding the woken up fd
 */
void mgmtRequestWriteInit(const unsigned int, TSelectorKey* key);

#endif // MANAGEMENT_REQUEST_H
