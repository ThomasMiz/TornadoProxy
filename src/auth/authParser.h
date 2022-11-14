#ifndef AUTH_PARSER_H
#define AUTH_PARSER_H

#include "../buffer.h"

#define AUTH_UNAME_MAX_LENGTH 0xFF
#define AUTH_PASSWD_MAX_LENGTH 0xFF
#define AUTH_VERSION_1 0x01

typedef enum TAuthState {
    AUTH_VERSION = 0,    // The parser is waiting for the client version
    AUTH_ULEN,           // The parser is waiting for the username length
    AUTH_UNAME,          // The parser is reading the username
    AUTH_PLEN,           // The parser is waiting for the password length
    AUTH_PASSWD,         // The parser is reading the password
    AUTH_END,            // All read for this state.
    AUTH_INVALID_VERSION // Client send a version != of 5
} TAuthState;

typedef enum TAuthVerification {
    AUTH_SUCCESSFUL = 0,
    AUTH_ACCESS_DENIED
} TAuthVerification;

typedef struct TAuthParser {
    TAuthState state;

    // Reading finishes when totalBytes == readBytes
    uint8_t totalBytes; // Bytes to be read, used for password and username
    uint8_t readBytes;  // Bytes read

    char uname[AUTH_UNAME_MAX_LENGTH + 1];
    char passwd[AUTH_PASSWD_MAX_LENGTH + 1];

    // Stores if the client has been successfully authenticated or not.
    TAuthVerification verification;
} TAuthParser;

void initAuthParser(TAuthParser* p);
TAuthState authParse(TAuthParser* p, struct buffer* buffer);
uint8_t hasAuthReadEnded(TAuthParser* p);

/* 0 if ok 1 if errors */
uint8_t fillAuthAnswer(TAuthParser* p, struct buffer* buffer);

#endif // NEGOTIATION_PARSER_H
