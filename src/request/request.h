#ifndef REQUEST_H
#define REQUEST_H

#include "../selector.h"
#include "requestParser.h"

/**
 * @brief Handler to initialize resources when the REQUEST_READ state is reached
 *
 * @param state the state from which the state machine arrived
 * @param key Selector key that holds information regarding the woken up fd
 */
void requestReadInit(const unsigned state, TSelectorKey* key);

/**
 * @brief Handler to read from ready file descriptor when inside REQUEST_READ state
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned requestRead(TSelectorKey* key);

/**
 * @brief Handler to write to ready file descriptor when inside REQUEST_WRITE state
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned requestWrite(TSelectorKey* key);

/**
 * @brief Handler to manage the resolution of host names when the detached thread finishes its process
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned requestResolveDone(TSelectorKey* key);

/**
 * @brief Fills the buffer inside the Selector Key with a request answer error code
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned fillRequestAnswerWitheErrorState(TSelectorKey* key, int state);

/**
 * @brief Waits util the connection is established
 * @param key Selector key that holds information regarding the ready fd
 * @returns resulting state machine state
 */
unsigned requestConecting(TSelectorKey* key);

/**
 * @brief Handler to initialize resources when the REQUEST_CONNECTING state is reached
 * @param key Selector key that holds information regarding the ready fd
 */
void requestConectingInit(const unsigned state, TSelectorKey* key);

#endif // NEGOTIATION_PARSER_H
