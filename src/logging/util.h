#ifndef _UTIL_H_
#define _UTIL_H_

#include <netdb.h>
#include <sys/socket.h>

int printSocketAddress(const struct sockaddr* address, char* addrBuffer);

const char* printFamily(int family);
const char* printType(int socktype);
const char* printProtocol(int protocol);
void printFlags(int flags);
char* printAddressPort(int family, struct sockaddr* addr, char outputBuf[]);

// Determina si dos sockets son iguales (misma direccion y puerto)
int sockAddrsEqual(const struct sockaddr* addr1, const struct sockaddr* addr2);

#endif