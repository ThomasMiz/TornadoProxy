#ifndef GENERIC_PARSER_H
#define GENERIC_PARSER_H

#include <stdint.h>

typedef struct TGenericParser {
    struct TParseState * state;
    uint8_t currentState;
    uint8_t (*isErrorState)(uint8_t state);
    uint8_t (*fillAnswer)(struct TGenericParser* p, struct buffer* buffer);
    void * data;
} TGenericParser;

typedef struct TParseState {
    uint8_t state;
    /* how to parse a character in a given state */
    uint8_t (*parseCharacter) (TGenericParser * p);
}TParseState;

/*void initNegotiationParser(TNegParser* p);
TNegState negotiationParse(TNegParser* p, struct buffer* buffer);
uint8_t hasNegotiationReadEnded(TNegParser* p);
uint8_t hasNegotiationErrors(TNegParser* p);*/

/* 0 if ok 1 if errors */
//uint8_t fillNegotiationAnswer(TNegParser* p, struct buffer* buffer);

/* 0 if ok 1 if errors */
//uint8_t changeAuthMethod(TNegParser* p, TNegMethod authMethod);*/

#endif // GENERIC_PARSER_H