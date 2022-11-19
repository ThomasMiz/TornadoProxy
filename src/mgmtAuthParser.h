#ifndef MGMT_AUTH_PARSER_H
#define MGMT_AUTH_PARSER_H

#include "buffer.h"
#include <stdbool.h>

#define M_AUTH_UNAME_MAX_LENGTH 0xFF
#define M_AUTH_PASSWD_MAX_LENGTH 0xFF

typedef enum MTAuthState {
    M_AUTH_ULEN,           // The parser is waiting for the username length
    M_AUTH_UNAME,          // The parser is reading the username
    M_AUTH_PLEN,           // The parser is waiting for the password length
    M_AUTH_PASSWD,         // The parser is reading the password
    M_AUTH_END,            // All read for this state.
    M_AUTH_INVALID_VERSION // Client send a version != of 5
} MTAuthState;

typedef enum MTAuthVerification {
    M_AUTH_SUCCESSFUL = 0,
    M_AUTH_ACCESS_DENIED
} MTAuthVerification;

typedef struct MTAuthParser {
    MTAuthState state;

    // Reading finishes when totalBytes == readBytes
    uint8_t totalBytes; // Bytes to be read, used for password and username
    uint8_t readBytes;  // Bytes read

    char uname[M_AUTH_UNAME_MAX_LENGTH + 1];
    char passwd[M_AUTH_PASSWD_MAX_LENGTH + 1];

    // Stores if the client has been successfully authenticated or not.
    MTAuthVerification verification;
} MTAuthParser;

typedef enum MTAuthRet {
    M_AUTHR_OK = 0,
    M_AUTHR_FULLBUFFER,
} MTAuthRet;

/**
 * @brief Initializes the auth parser.
 * @param p A pointer to previously allocated memory for the parser.
 */
void mgmtInitAuthParser(MTAuthParser* p);

/**
 * @brief Parses the characters recived in the buffer.
 * @param p The negotiation parser that will store the status of the negotiation.
 * @param buffer Contains the characters to parse.
 * @returns The status of the parser.
 */
MTAuthState mgmtAuthParse(MTAuthParser* p, struct buffer* buffer);

/**
 * @brief Checks if the given parser p has already finished the auth parsing.
 * @param p The auth parser whose state will be checked.
 * @returns true if the parser has reached AUTH_END or AUTH_INVALID_VERSION state, false otherwise.
 */
bool mgmtHasAuthReadEnded(MTAuthParser* p);

/**
 * @brief Checks if the given parser p has reached an error state.
 * @param p The auth parser whose state will be checked.
 * @returns true if the parser has reached AUTH_INVALID_VERSION state, false otherwise.
 */
bool mgmtHasAuthReadErrors(MTAuthParser* p);

/**
 * @brief Fills a valid answer for the auth, using the verification field of the parser, that has to
 * be previously setted acordingly
 * @param p The verification field will be retrived from this parser.
 * @param buffer The answer will be written in this buffer.
 * @returns AUTHR_OK if the answer was stored correctly, AUTHR_FULLBUFFER if there was no enough space in the buffer.
 */
MTAuthRet mgmtFillAuthAnswer(MTAuthParser* p, struct buffer* buffer);

#endif // MGMT_AUTH_PARSER_
