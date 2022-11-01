#ifndef NEGOTIATION_H
#define NEGOTIATION_H

#include <stdint.h>

#define NEG_METHOD_NO_AUTH 0x00
#define NEG_METHOD_PASS 0x02
#define NEG_METHOD_NO_MATCH 0xFF

typedef enum negState {
    NEG_VERSION = 0,  // The parser is waiting for the client version
    NEG_METHOD_COUNT, // The parser is waiting for the number of methos
    NEG_METHODS,      // The parser is reading methods
    NEG_END,          // All read for this state.
    NEG_ERROR
} negState;

typedef struct negParser {
    negState state;
    uint8_t authMethod;
    uint8_t pendingMethods;
} negParser;

negParser* newNegotiationParser();
negState negotiationRead(negParser* p, uint8_t* buffer, int bufferSize);
void freeNegotiationParser(negParser* p);
#endif // NEGOTIATION_H