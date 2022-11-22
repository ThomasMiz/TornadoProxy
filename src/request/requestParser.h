#ifndef REQUEST_PARSER_H
#define REQUEST_PARSER_H

#include "../buffer.h"
#include <netinet/ip.h>
#include <stdint.h>
#include <sys/types.h>

/** Parses a client request for SOCKS V5 as described in RFC 1928 (part 4 and 5):
   4.  Requests

   Once the method-dependent subnegotiation has completed, the client
   sends the request details.  If the negotiated method includes
   encapsulation for purposes of integrity checking and/or
   confidentiality, these requests MUST be encapsulated in the method-
   dependent encapsulation.

   The SOCKS request is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:
          o  VER    protocol version: X'05'
          o  CMD
             o  CONNECT X'01'   This implementation just supports parsing connect CMD
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT desired destination port in network octet
             order

   The SOCKS server will typically evaluate the request based on source
   and destination addresses, and return one or more reply messages, as
   appropriate for the request type.

    5.  Addressing

   In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
   the type of address contained within the field:

          o  X'01'

   the address is a version-4 IP address, with a length of 4 octets

          o  X'03'

   the address field contains a fully-qualified domain name.  The first
   octet of the address field contains the number of octets of name that
   follow, there is no terminating NUL octet.

          o  X'04'

   the address is a version-6 IP address, with a length of 16 octets.

   The method fillRequestAnswer fills the answer after parsing all the data based on
   the part 6 of the RFC 1928. It always fills with 0s the fields BND.ADDR and BND.PORT

   6.  Replies

   The SOCKS request information is sent by the client as soon as it has
   established a connection to the SOCKS server, and completed the
   authentication negotiations.  The server evaluates the request, and
   returns a reply formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  REP    Reply field:
             o  X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
          o  RSV    RESERVED
          o  ATYP   address type of following address

             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  BND.ADDR       server bound address
          o  BND.PORT       server bound port in network octet order

   Fields marked RESERVED (RSV) must be set to X'00'.

   If the chosen method includes encapsulation for purposes of
   authentication, integrity and/or confidentiality, the replies are
   encapsulated in the method-dependent encapsulation.
 *
 * */

enum TReqCmd {
    REQ_CMD_CONNECT = 0x01,
    REQ_CMD_BIND = 0x02,
    REQ_CMD_UDP = 0x03
};

enum TReqAtyp {
    REQ_ATYP_IPV4 = 0x01,
    REQ_ATYP_DOMAINNAME = 0x03,
    REQ_ATYP_IPV6 = 0x04
};

#define PORT_BYTE_LENGHT 2
#define REQ_MAX_DN_LENGHT 0xFF

typedef enum TReqState {
    REQ_VERSION = 0, // The parser is waiting for the client version
    REQ_CMD,         // The parser is waiting for CMD (CONNECT/BIND/UDP)
    REQ_RSV,         // The parser is waiting for the reserved space X'00'
    REQ_ATYP,        // The parser is waiting for the address type
    REQ_DN_LENGHT,   // If atype is 0x03, read the domainname length
    REQ_DST_ADDR,    // The parser is reading the desired destination address
    REQ_DST_PORT,    // The parser is reading the desired destination port in network octet order
    REQ_ERROR,
    REQ_ENDED
} TReqState;

typedef enum TReqStatus {
    REQ_SUCCEDED = 0,
    REQ_ERROR_GENERAL_FAILURE,
    REQ_ERROR_CONNECTION_NOT_ALLOWED,
    REQ_ERROR_NTW_UNREACHABLE,
    REQ_ERROR_HOST_UNREACHABLE,
    REQ_ERROR_CONNECTION_REFUSED,
    REQ_ERROR_TTL_EXPIRED,
    REQ_ERROR_COMMAND_NOT_SUPPORTED,
    REQ_ERROR_ADDRESS_TYPE_NOT_SUPPORTED,
} TReqStatus;

typedef union TAddress {
    struct in_addr ipv4;
    uint8_t domainname[REQ_MAX_DN_LENGHT + 1];
    struct in6_addr ipv6;

    // Used to set bytes without considering their meaning
    uint8_t bytes[REQ_MAX_DN_LENGHT + 1];
} TAddress;

typedef struct TReqParser {
    TReqState state;
    TReqStatus status;
    uint8_t atyp;
    uint8_t totalAtypBytes; // Used to know read bytes for atyp
    uint8_t readBytes;
    TAddress address;
    in_port_t port;
} TReqParser;

typedef enum TReqRet {
    REQR_OK = 0,
    REQR_FULLBUFFER,
} TReqRet;

const char* reqParserToString(const TReqParser* p);

/**
 * @brief Initializes the request parser.
 * @param p A pointer to previously allocated memory for the parser.
 */
void initRequestParser(TReqParser* p);

/**
 * @brief Parses the characters recived in the buffer.
 * @param p The request parser that will store the status of the request.
 * @param buffer Contains the characters to parse.
 * @returns The status of the parser.
 */
TReqState requestParse(TReqParser* p, struct buffer* buffer);

/**
 * @brief Checks if the given parser p has already finished the request parsing.
 * @param p The request parser whose state will be checked.
 * @returns true if the parser has reached  REQ_ERROR or REQ_ENDED state, false otherwise.
 */
uint8_t hasRequestReadEnded(TReqParser* p);

/**
 * @brief Checks if the given parser p has reached an error state.
 * @param p The request parser whose state will be checked.
 * @returns true if the parser has reached REQ_ERROR state, false otherwise.
 */
uint8_t hasRequestErrors(TReqParser* p);

/**
 * @brief Fills a valid answer for the request based on the parser auth method required
 * @param p The 'Reply field' (REP) will be retrived from this parser.
 * @param buffer The answer will be written in this buffer.
 * @returns REQR_OK if the answer was stored correctly, REQR_FULLBUFFER if there was no enough space in the buffer.
 */
TReqRet fillRequestAnswer(TReqParser* p, struct buffer* buffer);

#endif /* REQUEST_PARSER_H */
