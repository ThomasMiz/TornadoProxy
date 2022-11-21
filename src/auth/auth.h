#ifndef AUTH_H
#define AUTH_H

#include "../selector.h"
#include "authParser.h"

/**
 * @brief Handler to initialize resources when the AUTH_READ state is reached
 *
 * @param state the state from which the state machine arrived
 * @param key Selector key that holds information regarding the woken up fd
 */
void authReadInit(const unsigned state, TSelectorKey* key);

/**
 * @brief Handler to read from ready file descriptor inside the AUTH_READ state
 * @param state the state from which the state machine arrived
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned authRead(TSelectorKey* key);

/**
 * @brief Handler to write to ready file descriptor inside the AUTH_WRITE state
 * @param state the state from which the state machine arrived
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned authWrite(TSelectorKey* key);

#endif // AUTH_H
