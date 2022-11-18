#include "request.h"
#include "../logger.h"
#include "../socks5.h"
#include "../util.h"
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "../netutils.h"
#include <errno.h>


static unsigned requestProcess(TSelectorKey* key);
static void* requestNameResolution(void* data);
static unsigned startConnection(TSelectorKey * key);
static TReqStatus connectErrorToRequestStatus(int e);

void requestReadInit(const unsigned state, TSelectorKey* key) {
    log(DEBUG, "[Req read] init at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);
    initRequestParser(&data->client.reqParser);
}

unsigned requestRead(TSelectorKey* key) {
    log(DEBUG, "[Req read: INF] read at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->clientBuffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    log(DEBUG, "[Req read: INF]  %ld bytes from client %d ", readCount, key->fd);
    if (readCount <= 0) {
        return ERROR;
    }
    buffer_write_adv(&data->clientBuffer, readCount);
    requestParse(&data->client.reqParser, &data->clientBuffer);
    if (hasRequestReadEnded(&data->client.reqParser)) {
        if (!hasRequestErrors(&data->client.reqParser)) {
            return requestProcess(key);
        }
        log(LOG_ERROR, "Error parsing the request at fd %d", key->fd);
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

    log(DEBUG, "[Req read - process] init process for fd: %d", key->fd);

    if (atyp == REQ_ATYP_IPV4) {
        log(DEBUG, "[Req read - process] REQ_ATYP_IPV4 port: %d for fd: %d", data->client.reqParser.port, key->fd);
        struct sockaddr_in* sockaddr = malloc(sizeof(struct sockaddr_in));
        data->originResolution = calloc(1, sizeof(struct addrinfo));
        if (sockaddr == NULL) {
            log(DEBUG, "[Req read - process] malloc error for fd: %d", key->fd);
            goto finally;
        } else if (data->originResolution == NULL) {
            free(sockaddr);
            log(DEBUG, "[Req read - process] malloc error for fd: %d", key->fd);
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

        return startConnection(key);
    }

    if (atyp == REQ_ATYP_IPV6) {
        log(DEBUG, "[Req read - process] REQ_ATYP_IPV6 port: %d for fd: %d", data->client.reqParser.port, key->fd);
        struct sockaddr_in6* sockaddr = malloc(sizeof(struct sockaddr_in6));
        data->originResolution = calloc(1, sizeof(struct addrinfo));
        if (sockaddr == NULL) {
            log(DEBUG, "[Req read - process] malloc error for fd: %d", key->fd);
            goto finally;
        } else if (data->originResolution == NULL) {
            free(sockaddr);
            log(DEBUG, "[Req read - process] malloc error for fd: %d", key->fd);
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

        return startConnection(key);
    }

    if (atyp == REQ_ATYP_DOMAINNAME) {
        log(DEBUG, "[Req read - process] REQ_ATYP_DOMAINNAME port: %d for fd: %d", data->client.reqParser.port, key->fd);
        pthread_t tid;
        TSelectorKey* key2 = malloc(sizeof(*key));
        memcpy(key2, key, sizeof(*key2));
        if (pthread_create(&tid, NULL, requestNameResolution, key2) == -1) {
            log(DEBUG, "[Req read - process] thread error fd: %d", key->fd);
            goto finally;
        }
        return REQUEST_RESOLV;
    }

finally:
    fillRequestAnswerWitheErrorState(key, REQ_ERROR_GENERAL_FAILURE);
    return REQUEST_WRITE;
}

static void* requestNameResolution(void* data) {
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
        log(LOG_ERROR, "[getaddrinfo error] for fd: %d", key->fd);
        c->originResolution = NULL;
    }
    selector_notify_block(key->s, key->fd);
    free(data);
    return NULL;
}

unsigned requestResolveDone(TSelectorKey* key) {
    TClientData* data = ATTACHMENT(key);
    log(DEBUG, "[requestResolveDone] for fd: %d", key->fd);
    struct addrinfo *ailist, *aip;

    ailist = data->originResolution;
    char addr[64];
    for (aip = ailist; aip != NULL; aip = aip->ai_next) {
        printFlags(aip);
        printf(" family: %s ", printFamily(aip));
        printf(" type: %s ", printType(aip));
        printf(" protocol %s ", printProtocol(aip));
        printf("\n\thost %s", aip->ai_canonname ? aip->ai_canonname : "-");
        printf("address: %s", printAddressPort(aip, addr));
        putchar('\n');
    }

    if (ailist == NULL) {
        return fillRequestAnswerWitheErrorState(key, REQ_ERROR_HOST_UNREACHABLE);
    }
    return startConnection(key);
}

unsigned fillRequestAnswerWitheErrorState(TSelectorKey* key, int status) {
    TReqParser * p = &ATTACHMENT(key)->client.reqParser;

    p->state = REQ_ERROR;
    p->status = status;
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillRequestAnswer(p, &ATTACHMENT(key)->originBuffer)) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

unsigned requestWrite(TSelectorKey* key) {
    TClientData* data = ATTACHMENT(key);
    log(DEBUG, "rw p.state = %d ", data->client.reqParser.state);
    size_t writeLimit;    // how many bytes we want to send
    ssize_t writeCount;   // how many bytes where written
    uint8_t* writeBuffer; // buffer that stores the data to be sended

    writeBuffer = buffer_read_ptr(&data->originBuffer, &writeLimit);
    writeCount = send(data->clientFd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        log(LOG_ERROR, "send() at fd %d", key->fd);
        return ERROR;
    }
    if (writeCount == 0) {
        log(LOG_ERROR, "Failed to send(), client closed connection unexpectedly at fd %d", key->fd);
        return ERROR;
    }
    log(DEBUG, "[Req write: INF]  %ld bytes to client %d ", writeCount, key->fd);
    buffer_read_adv(&data->originBuffer, writeCount);

    if (buffer_can_read(&data->originBuffer)) {
        return REQUEST_WRITE;
    }

    if (hasRequestErrors(&data->client.reqParser) || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        log(DEBUG, "requestWrite error %d ", key->fd);
        return ERROR;
    }
    log(DEBUG, "requestWrite to copy %d ", key->fd);
    return COPY;
}

void requestConectingInit(const unsigned state, TSelectorKey* key) {
    log(DEBUG, "[Req con: init] ended for fd: %d", key->fd);
}

unsigned requestConecting(TSelectorKey* key) {
    TClientData* d = ATTACHMENT(key);
    TFdInterests curr_interests;
    selector_get_interests_key(key, &curr_interests);

    /*char buf[BUFFER_SIZE];
    sockaddr_to_human(buf, BUFFER_SIZE, d->originResolution->ai_addr);
    log(DEBUG, "Checking connection status to %s", buf);*/

    int error = 0;
    if (getsockopt(d->originFd, SOL_SOCKET, SO_ERROR, &error, &(socklen_t){sizeof(int)})) {
        return fillRequestAnswerWitheErrorState(key, REQ_ERROR_GENERAL_FAILURE);
    }

    if (error) {
        return fillRequestAnswerWitheErrorState(key, connectErrorToRequestStatus(error));
    }

    /*selector_set_interest(key->s, d->originFd, OP_WRITE);
    selector_set_interest(key->s, d->clientFd, OP_WRITE);*/
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillRequestAnswer(&d->client.reqParser, &d->originBuffer)) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

static unsigned startConnection(TSelectorKey * key) {
    TClientData* d = ATTACHMENT(key);

    d->originFd = socket(d->originResolution->ai_family, SOCK_STREAM | SOCK_NONBLOCK, d->originResolution->ai_protocol);
    if (d->originFd < 0) {
        return ERROR;
    }

    selector_fd_set_nio(d->originFd);
    char address_buf[1024];
    sockaddr_to_human(address_buf, 1024, d->originResolution->ai_addr);
    printf("Connecting to %s\n", address_buf);
    if (connect(d->originFd, d->originResolution->ai_addr, d->originResolution->ai_addrlen) == 0 || errno == EINPROGRESS) {
        if (selector_register(key->s, d->originFd, get_state_handler(), OP_WRITE, d) != SELECTOR_SUCCESS || SELECTOR_SUCCESS != selector_set_interest(key->s, key->fd, OP_NOOP)) {
            return ERROR;
        }
        return REQUEST_CONNECTING;
    }
    log(DEBUG, "connection error in fd %d", key->fd);

    //Could not connect to the first address, try with the next one, if exists
    if(d->originResolution->ai_next != NULL){
        close(d->originFd);
        struct addrinfo * next = d->originResolution->ai_next;
        d->originResolution->ai_next = NULL;
        freeaddrinfo(d->originResolution);
        d->originResolution = next;
        return startConnection(key);
    }
    //Return a connection error after trying to connect to all the addresses
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
