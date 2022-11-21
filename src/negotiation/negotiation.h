#ifndef NEGOTIATION_H
#define NEGOTIATION_H

#include "../selector.h"
#include "negotiationParser.h"

/**
 * @brief Handler to initialize resources when the NEGOTIATION_READ state is reached
 *
 * @param state the state from which the state machine arrived
 * @param key Selector key that holds information regarding the woken up fd
 */
void negotiationReadInit(const unsigned state, TSelectorKey* key);

/**
 * @brief Handler to read from ready file descriptor when inside NEGOTIATION_READ state
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned negotiationRead(TSelectorKey* key);

/**
 * @brief Handler to write to ready file descriptor when inside NEGOTIATION_WRITE state
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned negotiationWrite(TSelectorKey* key);

#endif // NEGOTIATION_H
