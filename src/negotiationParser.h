#ifndef NEGOTIATION_PARSER_H
#define NEGOTIATION_PARSER_H

#include "buffer.h"

enum TNegMethod {
    NEG_METHOD_NO_AUTH = 0x00,
    NEG_METHOD_PASS = 0x02,
    NEG_METHOD_NO_MATCH = 0xFF
};
typedef enum TNegState {
    NEG_VERSION = 0,  // The parser is waiting for the client version
    NEG_METHOD_COUNT, // The parser is waiting for the number of methos
    NEG_METHODS,      // The parser is reading methods
    NEG_END,          // All read for this state.
    NEG_ERROR
} TNegState;

typedef struct TNegParser {
    TNegState state;
    uint8_t authMethod;
    uint8_t pendingMethods;
} TNegParser;

void initNegotiationParser(TNegParser* p);
TNegState negotiationParse(TNegParser* p, struct buffer* buffer);
uint8_t hasNegotiationReadEnded(TNegParser* p);
uint8_t hasNegotiationErrors(TNegParser* p);

/* 0 if ok -1 if errors */
uint8_t fillNegotiationAnswer(TNegParser* p, struct buffer* buffer);

#endif // NEGOTIATION_PARSER_H