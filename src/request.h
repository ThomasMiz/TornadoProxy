#ifndef REQUEST_H
#define REQUEST_H

#include <stdint.h>

#define REQ_CMD_CONNECT 0x01
#define REQ_CMD_BIND 0x02
#define REQ_CMD_UDP 0x03

#define REQ_ATYP_IPV4 0x01
#define REQ_ATYP_DOMAINNAME 0x03
#define REQ_ATYP_IPV6 0x04

#define IPV4_BYTE_LENGHT 4
#define IPV6_BYTE_LENGHT 16
#define PORT_BYTE_LENGHT 2

typedef enum reqState {
    REQ_SUCCEDED = 0,
    REQ_ERROR_GENERAL_FAILURE,
    REQ_ERROR_CONNECTION_NOT_ALLOWED,
    REQ_ERROR_NTW_UNREACHABLE,
    REQ_ERROR_HOST_UNREACHABLE,
    REQ_ERROR_CONNECTION_REFUSED,
    REQ_ERROR_TTL_EXPIRED,
    REQ_ERROR_COMMAND_NOT_SUPPORTED,
    REQ_ERROR_ADDRESS_TYPE_NOT_SUPPORTED,
    REQ_VERSION,   // The parser is waiting for the client version
    REQ_CMD,       // The parser is waiting for CMD (Connect/bind/udp)
    REQ_RSV,       // The parser is waiting for the reserved space X'00'
    REQ_ATYP,      // The parser is waiting for the address type
    REQ_DN_LENGHT, // If atype is 0x03, read the domainname length
    REQ_DST_ADDR,
    REQ_DST_PORT
} reqState;

typedef union naddress {
    uint8_t ipv4[IPV4_BYTE_LENGHT];
    uint8_t* domainname;
    uint8_t ipv6[IPV6_BYTE_LENGHT];
} naddress;

typedef struct reqParser {
    reqState state;
    uint8_t atyp;
    uint8_t totalAtypBytes;
    uint8_t readBytes; // Used to know read bytes for atyp and port
    naddress address;
    uint16_t port;
} reqParser;

reqParser* newRequestParser();
reqState requestRead(reqParser* p, uint8_t* buffer, int bufferSize);
void freeRequestParser(reqParser* p);

#endif /* REQUEST_H */