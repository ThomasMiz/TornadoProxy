#ifndef _UTIL_H_
#define _UTIL_H_

#include <netdb.h>
#include <sys/socket.h>

const char* printSocketAddressWith(const struct sockaddr* address, const char separator);
const char* printSocketAddress(const struct sockaddr* address);

const char* printFamily(int family);
const char* printType(int socktype);
const char* printProtocol(int protocol);
const char* printFlags(int flags);
const char* printAddressPort(int family, struct sockaddr* address);

// Determina si dos sockets son iguales (misma direccion y puerto)
int sockAddrsEqual(const struct sockaddr* addr1, const struct sockaddr* addr2);

#endif
