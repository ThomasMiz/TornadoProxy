#ifndef NEGOTIATION_PARSER_H
#define NEGOTIATION_PARSER_H

#include "../buffer.h"
#include <stdbool.h>

/** Parses the auth methods negotiation between the client and the server, following RFC 1928
 *
 * The client connects to the server, and sends a version identifier/method selection message:

                   +----+----------+----------+
                   |VER | NMETHODS | METHODS  |
                   +----+----------+----------+
                   | 1  |    1     | 1 to 255 |
                   +----+----------+----------+

   The VER field is set to X'05' for this version of the protocol.  The NMETHODS field contains the
   number of method identifier octets that appear in the METHODS field.

   The server selects from one of the methods given in METHODS, and sends a METHOD selection message:

                         +----+--------+
                         |VER | METHOD |
                         +----+--------+
                         | 1  |   1    |
                         +----+--------+

   If the selected METHOD is X'FF', none of the methods listed by the client are acceptable, and the
   client MUST close the connection.

   The values currently defined for METHOD are:
          o  X'00' NO AUTHENTICATION REQUIRED
          o  X'01' GSSAPI
          o  X'02' USERNAME/PASSWORD
          o  X'03' to X'7F' IANA ASSIGNED
          o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
          o  X'FF' NO ACCEPTABLE METHODS
 * */

/* Just supporting NO AUTHENTICATION REQUIRED and USERNAME/PASSWORD auth methods */
typedef enum TNegMethod {
    NEG_METHOD_NO_AUTH = 0x00,
    NEG_METHOD_PASS = 0x02,
    NEG_METHOD_NO_MATCH = 0xFF
} TNegMethod;

typedef enum TNegState {
    NEG_VERSION = 0,  // The parser is waiting for the client version
    NEG_METHOD_COUNT, // The parser is waiting for the number of methos
    NEG_METHODS,      // The parser is reading methods
    NEG_END,          // All read for this state
    NEG_ERROR         // If the parser arrives to this state, errors where found while parsing
} TNegState;

typedef struct TNegParser {
    TNegState state;
    TNegMethod authMethod;
    uint8_t pendingMethods;
} TNegParser;

typedef enum TNegRet {
    NEGR_OK = 0,
    NEGR_FULLBUFFER,
    NEGR_INVALIDMETHOD,
} TNegRet;

/**
 * @brief Initializes the negotiation parser.
 * @param p A pointer to previously allocated memory for the parser.
 */
void initNegotiationParser(TNegParser* p);

/**
 * @brief Parses the characters recived in the buffer.
 * @param p The negotiation parser that will store the status of the negotiation.
 * @param buffer Contains the characters to parse.
 * @returns The status of the parser.
 */
TNegState negotiationParse(TNegParser* p, struct buffer* buffer);

/**
 * @brief Checks if the given parser p has already finished the negotiation parsing.
 * @param p The negotiation parser whose state will be checked.
 * @returns true if the parser has reached NEQ_END or NEG_ERROR state, false otherwise.
 */
bool hasNegotiationReadEnded(TNegParser* p);

/**
 * @brief Checks if the given parser p has reached an error state.
 * @param p The negotiation parser whose state will be checked.
 * @returns true if the parser has reached NEG_ERROR state, false otherwise.
 */
bool hasNegotiationErrors(TNegParser* p);

/**
 * @brief Fills a valid answer for the negotiation based on the parser auth method required
 * @param p The negotiated auth method will be retrived from this parser.
 * @param buffer The answer will be written in this buffer.
 * @returns NEGR_OK if the answer was stored correctly, NEGR_FULLBUFFER if there was no enough space in the buffer.
 */
TNegRet fillNegotiationAnswer(TNegParser* p, struct buffer* buffer);

/**
 * @brief Allows to change the required auth method for the negotiation parsers.
 * @param authMethod the new auth method to ask for
 * @returns NEGR_OK if the auth method is valid, NEGR_INVALIDMETHOD otherwise.
 */
TNegRet changeAuthMethod(TNegMethod authMethod);

/**
 * @brief Gets the auth method required for the negotiation parsers.
 * @returns required auth method.
 */
uint8_t getAuthMethod();

#endif // NEGOTIATION_PARSER_H
