#include "util.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ADDRSTR_BUFLEN 64

const char* printFamily(int family) {
    switch (family) {
        case AF_INET:
            return "IPv4";
        case AF_INET6:
            return "IPv6";
        case AF_UNIX:
            return "unix";
        case AF_UNSPEC:
            return "unspecified";
    }

    return "unknown";
}

const char* printType(int socktype) {
    switch (socktype) {
        case SOCK_STREAM:
            return "stream";
        case SOCK_DGRAM:
            return "datagram";
        case SOCK_SEQPACKET:
            return "seqpacket";
        case SOCK_RAW:
            return "raw";
    }

    return "unknown";
}

const char* printProtocol(int protocol) {
    switch (protocol) {
        case 0:
            return "default";
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_RAW:
            return "raw";
    }

    return "unknown";
}

void printFlags(int flags) {
    printf("flags");
    if (flags == 0) {
        printf(" 0");
    } else {
        if (flags & AI_PASSIVE)
            printf(" passive");
        if (flags & AI_CANONNAME)
            printf(" canon");
        if (flags & AI_NUMERICHOST)
            printf(" numhost");
        if (flags & AI_NUMERICSERV)
            printf(" numserv");
        if (flags & AI_V4MAPPED)
            printf(" v4mapped");
        if (flags & AI_ALL)
            printf(" all");
    }
}

const char* printAddressPort(int family, struct sockaddr* address) {
    if (address == NULL)
        return "unknown address";

    static char addrBuffer[ADDRSTR_BUFLEN];
    char abuf[INET6_ADDRSTRLEN];
    const char* addrAux;
    if (family == AF_INET) {
        struct sockaddr_in* sinp;
        sinp = (struct sockaddr_in*)address;
        addrAux = inet_ntop(AF_INET, &sinp->sin_addr, abuf, INET_ADDRSTRLEN);
        if (addrAux == NULL)
            addrAux = "unknown";
        strcpy(addrBuffer, addrAux);
        if (sinp->sin_port != 0) {
            sprintf(addrBuffer + strlen(addrBuffer), ": %d", ntohs(sinp->sin_port));
        }
    } else if (family == AF_INET6) {
        struct sockaddr_in6* sinp;
        sinp = (struct sockaddr_in6*)address;
        addrAux = inet_ntop(AF_INET6, &sinp->sin6_addr, abuf, INET6_ADDRSTRLEN);
        if (addrAux == NULL)
            addrAux = "unknown";
        strcpy(addrBuffer, addrAux);
        if (sinp->sin6_port != 0)
            sprintf(addrBuffer + strlen(addrBuffer), ": %d", ntohs(sinp->sin6_port));
    } else
        strcpy(addrBuffer, "unknown");
    return addrBuffer;
}

const char* printSocketAddress(const struct sockaddr* address) {
    if (address == NULL)
        return "unknown address";

    static char addrBuffer[ADDRSTR_BUFLEN];
    void* numericAddress;
    in_port_t port;

    switch (address->sa_family) {
        case AF_INET:
            numericAddress = &((struct sockaddr_in*)address)->sin_addr;
            port = ntohs(((struct sockaddr_in*)address)->sin_port);
            break;
        case AF_INET6:
            numericAddress = &((struct sockaddr_in6*)address)->sin6_addr;
            port = ntohs(((struct sockaddr_in6*)address)->sin6_port);
            break;
        default:
            strcpy(addrBuffer, "[unknown type]"); // Unhandled type
            return 0;
    }
    // Convert binary to printable address
    if (inet_ntop(address->sa_family, numericAddress, addrBuffer, INET6_ADDRSTRLEN) == NULL)
        strcpy(addrBuffer, "[invalid address]");
    else {
        if (port != 0)
            sprintf(addrBuffer + strlen(addrBuffer), ":%u", port);
    }
    return addrBuffer;
}

int sockAddrsEqual(const struct sockaddr* addr1, const struct sockaddr* addr2) {
    if (addr1 == NULL || addr2 == NULL)
        return addr1 == addr2;
    else if (addr1->sa_family != addr2->sa_family)
        return 0;
    else if (addr1->sa_family == AF_INET) {
        struct sockaddr_in* ipv4Addr1 = (struct sockaddr_in*)addr1;
        struct sockaddr_in* ipv4Addr2 = (struct sockaddr_in*)addr2;
        return ipv4Addr1->sin_addr.s_addr == ipv4Addr2->sin_addr.s_addr && ipv4Addr1->sin_port == ipv4Addr2->sin_port;
    } else if (addr1->sa_family == AF_INET6) {
        struct sockaddr_in6* ipv6Addr1 = (struct sockaddr_in6*)addr1;
        struct sockaddr_in6* ipv6Addr2 = (struct sockaddr_in6*)addr2;
        return memcmp(&ipv6Addr1->sin6_addr, &ipv6Addr2->sin6_addr, sizeof(struct in6_addr)) == 0 && ipv6Addr1->sin6_port == ipv6Addr2->sin6_port;
    } else
        return 0;
}
