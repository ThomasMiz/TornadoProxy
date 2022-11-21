#include "request.h"
#include "../logging/logger.h"
#include "../logging/util.h"
#include "../socks5.h"
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

static unsigned requestProcess(TSelectorKey* key);
static void* requestNameResolution(void* data);
static unsigned startConnection(TSelectorKey* key);
static TReqStatus connectErrorToRequestStatus(int e);

void requestReadInit(const unsigned state, TSelectorKey* key) {
    logf(LOG_DEBUG, "requestReadInit: Init at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);
    initRequestParser(&data->client.reqParser);
}

unsigned requestRead(TSelectorKey* key) {
    logf(LOG_DEBUG, "requestRead: Read at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->clientBuffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    logf(LOG_DEBUG, "requestRead: %ld bytes from client %d", readCount, key->fd);
    if (readCount <= 0) {
        return ERROR;
    }
    buffer_write_adv(&data->clientBuffer, readCount);
    requestParse(&data->client.reqParser, &data->clientBuffer);
    if (hasRequestReadEnded(&data->client.reqParser)) {
        if (!hasRequestErrors(&data->client.reqParser)) {
            return requestProcess(key);
        }
        logf(LOG_ERROR, "requestRead: Error parsing the request at fd %d", key->fd);
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillRequestAnswer(&data->client.reqParser, &data->originBuffer)) {
            return ERROR;
        }
        return REQUEST_WRITE;
    }
    return REQUEST_READ;
}

static unsigned requestProcess(TSelectorKey* key) {
    TClientData* data = ATTACHMENT(key);
    TReqParser rp = data->client.reqParser;
    uint8_t atyp = rp.atyp;

    logf(LOG_DEBUG, "requestProcess: Init process for fd: %d", key->fd);

    if (atyp == REQ_ATYP_IPV4) {
        struct sockaddr_in* sockaddr = malloc(sizeof(struct sockaddr_in));
        data->originResolution = calloc(1, sizeof(struct addrinfo));
        if (sockaddr == NULL) {
            logf(LOG_DEBUG, "requestProcess: malloc error for fd: %d", key->fd);
            goto finally;
        } else if (data->originResolution == NULL) {
            free(sockaddr);
            logf(LOG_DEBUG, "requestProcess: malloc error for fd: %d", key->fd);
            goto finally;
        }
        *sockaddr = (struct sockaddr_in){
            .sin_family = AF_INET,
            .sin_addr = rp.address.ipv4,
            .sin_port = htons(rp.port),
        };

        *data->originResolution = (struct addrinfo){
            .ai_family = AF_INET,
            .ai_addr = (struct sockaddr*)sockaddr,
            .ai_addrlen = sizeof(*sockaddr),
        };

        logf(LOG_INFO, "Client %d requested to connect to IPv4 address %s", data->clientFd, printSocketAddress((struct sockaddr*)sockaddr));
        return startConnection(key);
    }

    if (atyp == REQ_ATYP_IPV6) {
        struct sockaddr_in6* sockaddr = malloc(sizeof(struct sockaddr_in6));
        data->originResolution = calloc(1, sizeof(struct addrinfo));
        if (sockaddr == NULL) {
            logf(LOG_DEBUG, "requestProcess: malloc error for fd: %d", key->fd);
            goto finally;
        } else if (data->originResolution == NULL) {
            free(sockaddr);
            logf(LOG_DEBUG, "requestProcess: malloc error for fd: %d", key->fd);
            goto finally;
        }
        *sockaddr = (struct sockaddr_in6){
            .sin6_family = AF_INET6,
            .sin6_addr = rp.address.ipv6,
            .sin6_port = htons(rp.port)};

        *data->originResolution = (struct addrinfo){
            .ai_family = AF_INET6,
            .ai_addr = (struct sockaddr*)sockaddr,
            .ai_addrlen = sizeof(*sockaddr),
        };

        logf(LOG_INFO, "Client %d requested to connect to IPv6 address %s", data->clientFd, printSocketAddress((struct sockaddr*)sockaddr));
        return startConnection(key);
    }

    if (atyp == REQ_ATYP_DOMAINNAME) {
        logf(LOG_INFO, "Client %d requested to connect to domain name %s:%d", data->clientFd, data->client.reqParser.address.domainname, data->client.reqParser.port);

        pthread_t tid;
        TSelectorKey* key2 = malloc(sizeof(*key));
        memcpy(key2, key, sizeof(*key2));
        if (pthread_create(&tid, NULL, requestNameResolution, key2) == -1) {
            logf(LOG_DEBUG, "requestProcess: thread error fd: %d", key->fd);
            goto finally;
        }
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            return ERROR;
        }

        return REQUEST_RESOLV;
    }

finally:
    fillRequestAnswerWitheErrorState(key, REQ_ERROR_GENERAL_FAILURE);
    return REQUEST_WRITE;
}

static void* requestNameResolution(void* data) {
    // WARNING: This function is run on a separate thread. Functions such as logging
    // will break if used from here. Modify with caution.
    TSelectorKey* key = (TSelectorKey*)data;
    TClientData* c = ATTACHMENT(key);

    pthread_detach(pthread_self());
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
        .ai_protocol = 0,
        .ai_canonname = NULL,
        .ai_addr = NULL,
        .ai_next = NULL,
    };

    char service[6] = {0};
    sprintf(service, "%d", (int)c->client.reqParser.port);

    int err = getaddrinfo((char*)c->client.reqParser.address.domainname, service, &hints, &(c->originResolution));
    if (err != 0) {
        c->originResolution = NULL;
    }
    selector_notify_block(key->s, key->fd);
    free(data);
    return NULL;
}

unsigned requestResolveDone(TSelectorKey* key) {
    TClientData* data = ATTACHMENT(key);
    logf(LOG_DEBUG, "requestResolveDone: for fd: %d, result:", key->fd);
    struct addrinfo *ailist, *aip;

    ailist = data->originResolution;
    for (aip = ailist; aip != NULL; aip = aip->ai_next) {
        logf(LOG_DEBUG, "--> family=%s, type=%s, protocol=%s, host=%s, address=%s flags=\"%s\"", printFamily(aip->ai_family),
             printType(aip->ai_socktype), printProtocol(aip->ai_protocol), aip->ai_canonname ? aip->ai_canonname : "-",
             printAddressPort(aip->ai_family, aip->ai_addr), printFlags(aip->ai_flags));
    }

    if (ailist == NULL) {
        logf(LOG_DEBUG, "Resolve of domain name requested by %d returned no results", key->fd);
        return fillRequestAnswerWitheErrorState(key, REQ_ERROR_HOST_UNREACHABLE);
    }

    return startConnection(key);
}

unsigned fillRequestAnswerWitheErrorState(TSelectorKey* key, int status) {
    TReqParser* p = &ATTACHMENT(key)->client.reqParser;

    p->state = REQ_ERROR;
    p->status = status;
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillRequestAnswer(p, &ATTACHMENT(key)->originBuffer)) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

unsigned requestWrite(TSelectorKey* key) {
    TClientData* data = ATTACHMENT(key);
    logf(LOG_DEBUG, "requestWrite: rw p.state = %d", data->client.reqParser.state);
    size_t writeLimit;    // how many bytes we want to send
    ssize_t writeCount;   // how many bytes where written
    uint8_t* writeBuffer; // buffer that stores the data to be sended

    writeBuffer = buffer_read_ptr(&data->originBuffer, &writeLimit);
    writeCount = send(data->clientFd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        logf(LOG_ERROR, "requestWrite: send() at fd %d", key->fd);
        return ERROR;
    }
    if (writeCount == 0) {
        logf(LOG_ERROR, "requestWrite: Failed to send(), client closed connection unexpectedly at fd %d", key->fd);
        return ERROR;
    }
    logf(LOG_DEBUG, "requestWrite: %ld bytes to client %d ", writeCount, key->fd);
    buffer_read_adv(&data->originBuffer, writeCount);

    if (buffer_can_read(&data->originBuffer)) {
        return REQUEST_WRITE;
    }

    if (hasRequestErrors(&data->client.reqParser) || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        logf(LOG_DEBUG, "requestWrite: error %d ", key->fd);
        return ERROR;
    }
    logf(LOG_DEBUG, "requestWrite: to copy %d ", key->fd);
    return COPY;
}

void requestConectingInit(const unsigned state, TSelectorKey* key) {
    logf(LOG_DEBUG, "requestConectingInit: ended for fd: %d", key->fd);
}

unsigned requestConecting(TSelectorKey* key) {
    TClientData* d = ATTACHMENT(key);
    TFdInterests curr_interests;
    selector_get_interests_key(key, &curr_interests);

    int error = 0;
    if (getsockopt(d->originFd, SOL_SOCKET, SO_ERROR, &error, &(socklen_t){sizeof(int)})) {
        logf(LOG_ERROR, "Failed to getsockopt for connection request from client %d", d->clientFd);
        return fillRequestAnswerWitheErrorState(key, REQ_ERROR_GENERAL_FAILURE);
    }

    if (error) {
        // Could not connect to the first address, try with the next one, if exists
        if (d->originResolution->ai_next == NULL) {
            logf(LOG_INFO, "Failed to fulfill connection request from client %d", d->clientFd);
            return fillRequestAnswerWitheErrorState(key, connectErrorToRequestStatus(error));
        } else {
            selector_unregister_fd_noclose(key->s, d->originFd);
            close(d->originFd);
            struct addrinfo* next = d->originResolution->ai_next;
            d->originResolution->ai_next = NULL;
            freeaddrinfo(d->originResolution);
            d->originResolution = next;
            return startConnection(key);
        }
    }

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillRequestAnswer(&d->client.reqParser, &d->originBuffer)) {
        return ERROR;
    }

    logf(LOG_INFO, "Successfully connected to %s as requested by client %d", printSocketAddress(d->originResolution->ai_addr), d->clientFd);
    return REQUEST_WRITE;
}

static unsigned startConnection(TSelectorKey* key) {
    TClientData* d = ATTACHMENT(key);

    d->originFd = socket(d->originResolution->ai_family, SOCK_STREAM | SOCK_NONBLOCK, d->originResolution->ai_protocol);
    if (d->originFd < 0) {
        d->originFd = socket(d->originResolution->ai_family, SOCK_STREAM, d->originResolution->ai_protocol);
    }
    if (d->originFd < 0) {
        logf(LOG_ERROR, "Failed to open socket for connection request from client %d", d->clientFd);
        return ERROR;
    }
    selector_fd_set_nio(d->originFd);

    logf(LOG_INFO, "Attempting to connect to %s as requested by client %d", printSocketAddress(d->originResolution->ai_addr), d->clientFd);

    if (connect(d->originFd, d->originResolution->ai_addr, d->originResolution->ai_addrlen) == 0 || errno == EINPROGRESS) {
        if (selector_register(key->s, d->originFd, getStateHandler(), OP_WRITE, d) != SELECTOR_SUCCESS || SELECTOR_SUCCESS != selector_set_interest(key->s, key->fd, OP_NOOP)) {
            logf(LOG_DEBUG, "startConnection: Failed to register and set interests for request by client fd %d", d->clientFd);
            return ERROR;
        }
        logf(LOG_DEBUG, "startConnection: Connect attempt in progress for request by client fd %d", d->clientFd);
        return REQUEST_CONNECTING;
    }

    logf(LOG_INFO, "Connect attempt to %s failed (requested by client %d)", printSocketAddress(d->originResolution->ai_addr), d->clientFd);

    // Could not connect to the first address, try with the next one, if exists
    if (d->originResolution->ai_next != NULL) {
        selector_unregister_fd_noclose(key->s, d->originFd);
        close(d->originFd);
        struct addrinfo* next = d->originResolution->ai_next;
        d->originResolution->ai_next = NULL;
        freeaddrinfo(d->originResolution);
        d->originResolution = next;
        return startConnection(key);
    }

    // Return a connection error after trying to connect to all the addresses
    logf(LOG_INFO, "Failed to fulfill connection request from client %d", d->clientFd);
    return fillRequestAnswerWitheErrorState(key, connectErrorToRequestStatus(errno));
}

static TReqStatus connectErrorToRequestStatus(int e) {
    switch (e) {
        case 0:
            return REQ_SUCCEDED;
        case ECONNREFUSED:
            return REQ_ERROR_CONNECTION_REFUSED;
        case EHOSTUNREACH:
            return REQ_ERROR_HOST_UNREACHABLE;
        case ENETUNREACH:
            return REQ_ERROR_NTW_UNREACHABLE;
        case ETIMEDOUT:
            return REQ_ERROR_TTL_EXPIRED;
        default:
            return REQ_ERROR_GENERAL_FAILURE;
    }
}
