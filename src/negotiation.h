#ifndef NEGOTIATION_H
#define NEGOTIATION_H

#include <stdint.h>

#define NEGOTIATION_METHOD_NO_AUTH 0x00
#define NEGOTIATION_METHOD_PASS 0x02
#define NEGOTIATION_METHOD_NO_MATCH 0xFF

typedef enum negState {
    VERSION = 0,  // The parser is waiting for the client version
    METHOD_COUNT, // The parser is waiting for the number of methos
    METHODS,      // The parser is reading methods
    END,          // All read for this state.
    ERROR
} negState;

typedef struct negParser {
    negState state;
    uint8_t acceptsNoAuth;
    uint8_t acceptsPass;
    uint8_t pendingMethods;
} negParser;

negParser* newNegotiationParser();
negState negotiationRead(negParser* p, uint8_t* buffer, int bufferSize);
void freeNegotiationParser(negParser* p);
#endif // NEGOTIATION_H