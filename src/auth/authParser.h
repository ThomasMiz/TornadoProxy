#ifndef AUTH_PARSER_H
#define AUTH_PARSER_H

#include "../buffer.h"
#include <stdbool.h>

#define AUTH_UNAME_MAX_LENGTH 0xFF
#define AUTH_PASSWD_MAX_LENGTH 0xFF
#define AUTH_VERSION_1 0x01

/** Parses Username/Password Authentication for SOCKS V5 as described in RFC 1929
 *
 * Once the SOCKS V5 server has started, and the client has selected the
   Username/Password Authentication protocol, the Username/Password
   subnegotiation begins.  This begins with the client producing a
   Username/Password request:

           +----+------+----------+------+----------+
           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
           +----+------+----------+------+----------+
           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
           +----+------+----------+------+----------+

   The VER field contains the current version of the subnegotiation,
   which is X'01'. The ULEN field contains the length of the UNAME field
   that follows. The UNAME field contains the username as known to the
   source operating system. The PLEN field contains the length of the
   PASSWD field that follows. The PASSWD field contains the password
   association with the given UNAME.

   The server verifies the supplied UNAME and PASSWD, and sends the
   following response:

                        +----+--------+
                        |VER | STATUS |
                        +----+--------+
                        | 1  |   1    |
                        +----+--------+

   A STATUS field of X'00' indicates success. If the server returns a
   `failure' (STATUS value other than X'00') status, it MUST close the
   connection.

 * */

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

typedef enum TAuthRet {
    AUTHR_OK = 0,
    AUTHR_FULLBUFFER,
} TAuthRet;

/**
 * @brief Initializes the auth parser.
 * @param p A pointer to previously allocated memory for the parser.
 */
void initAuthParser(TAuthParser* p);

/**
 * @brief Parses the characters recived in the buffer.
 * @param p The negotiation parser that will store the status of the negotiation.
 * @param buffer Contains the characters to parse.
 * @returns The status of the parser.
 */
TAuthState authParse(TAuthParser* p, struct buffer* buffer);

/**
 * @brief Checks if the given parser p has already finished the auth parsing.
 * @param p The auth parser whose state will be checked.
 * @returns true if the parser has reached AUTH_END or AUTH_INVALID_VERSION state, false otherwise.
 */
bool hasAuthReadEnded(TAuthParser* p);

/**
 * @brief Checks if the given parser p has reached an error state.
 * @param p The auth parser whose state will be checked.
 * @returns true if the parser has reached AUTH_INVALID_VERSION state, false otherwise.
 */
bool hasAuthReadErrors(TAuthParser* p);

/**
 * @brief Fills a valid answer for the auth, using the verification field of the parser, that has to
 * be previously setted acordingly
 * @param p The verification field will be retrived from this parser.
 * @param buffer The answer will be written in this buffer.
 * @returns AUTHR_OK if the answer was stored correctly, AUTHR_FULLBUFFER if there was no enough space in the buffer.
 */
TAuthRet fillAuthAnswer(TAuthParser* p, struct buffer* buffer);

#endif // NEGOTIATION_PARSER_H
