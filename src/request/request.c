#include "request.h"
#include "../socks5.h"
#include "../util.h"
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../logger.h"
#include <sys/socket.h>
#include <sys/types.h>

static unsigned requestProcess(TSelectorKey* key);
static void* requestNameResolution(void* data);

void requestReadInit(const unsigned state, TSelectorKey* key) {
   log(DEBUG,"[Req read] init at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);
    initRequestParser(&data->client.reqParser);
}

unsigned requestRead(TSelectorKey* key) {
    log(DEBUG,"[Req read: INF] read at socket fd %d", key->fd);
    TClientData* data = ATTACHMENT(key);

    size_t readLimit;    // how many bytes can be stored in the buffer
    ssize_t readCount;   // how many bytes where read from the client socket
    uint8_t* readBuffer; // here are going to be stored the bytes read from the client

    readBuffer = buffer_write_ptr(&data->clientBuffer, &readLimit);
    readCount = recv(key->fd, readBuffer, readLimit, 0);
    log(DEBUG,"[Req read: INF]  %ld bytes from client %d ", readCount, key->fd);
    if (readCount <= 0) {
        return ERROR;
    }

    buffer_write_adv(&data->clientBuffer, readCount);
    requestParse(&data->client.reqParser, &data->clientBuffer);
    if (hasRequestReadEnded(&data->client.reqParser)) {
        if (!hasRequestErrors(&data->client.reqParser)) {
            return requestProcess(key);
        }
        log(LOG_ERROR,"Error parsing the request at fd %d", key->fd);
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
        log(DEBUG, "[Req read - process] REQ_ATYP_IPV4 port: %d for fd: %d",data->client.reqParser.port, key->fd);
        struct sockaddr_in *sockaddr = malloc(sizeof(struct sockaddr_in));
        data->origin_resolution = calloc(1,sizeof(struct addrinfo));
        if(sockaddr == NULL){
            log(DEBUG, "[Req read - process] malloc error for fd: %d", key->fd);
            goto finally;
        }else if(data->origin_resolution == NULL){
            free(sockaddr);
            log(DEBUG, "[Req read - process] malloc error for fd: %d", key->fd);
            goto finally;
        }
        *sockaddr = (struct sockaddr_in) {
            .sin_family = AF_INET,
            .sin_addr = rp.address.ipv4,
            .sin_port = htons(rp.port),
        };

        *data->origin_resolution = (struct addrinfo)
        {
            .ai_family = AF_INET,
            .ai_addr = (struct sockaddr*)sockaddr,
            .ai_addrlen = sizeof(*sockaddr),
        };

        return REQUEST_CONNECTING;
    }

    if (atyp == REQ_ATYP_IPV6) {
        log(DEBUG, "[Req read - process] REQ_ATYP_IPV6 port: %d for fd: %d",data->client.reqParser.port, key->fd);
        struct sockaddr_in6 *sockaddr = malloc(sizeof(struct sockaddr_in6));
        data->origin_resolution = calloc(1,sizeof(struct addrinfo));
        if(sockaddr == NULL){
            log(DEBUG, "[Req read - process] malloc error for fd: %d", key->fd);
            goto finally;
        }else if(data->origin_resolution == NULL){
            free(sockaddr);
            log(DEBUG, "[Req read - process] malloc error for fd: %d", key->fd);
            goto finally;
        }
        *sockaddr = (struct sockaddr_in6) {
            .sin6_family = AF_INET6,
            .sin6_addr = rp.address.ipv6,
            .sin6_port = htons(rp.port)
        };

        *data->origin_resolution = (struct addrinfo) {
            .ai_family = AF_INET6,
            .ai_addr = (struct sockaddr*)sockaddr,
            .ai_addrlen = sizeof(*sockaddr),
        };

        return REQUEST_CONNECTING;
    }

    if (atyp == REQ_ATYP_DOMAINNAME) {
        log(DEBUG, "[Req read - process] REQ_ATYP_DOMAINNAME port: %d for fd: %d",data->client.reqParser.port, key->fd);
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
    fillRequestAnswerWithState(key, REQ_ERROR_GENERAL_FAILURE);
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

    int err = getaddrinfo((char*)c->client.reqParser.address.domainname, service, &hints, &(c->origin_resolution));
    if (err != 0) {
        // todo
    }
    selector_notify_block(key->s, key->fd);
    free(data);
    return NULL;
}

unsigned requestResolveDone(TSelectorKey* key) {
    TClientData* data = ATTACHMENT(key);

    struct addrinfo *ailist, *aip;

    ailist = data->origin_resolution;
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

    if(ailist == NULL){
        return fillRequestAnswerWithState(key, REQ_ERROR_GENERAL_FAILURE);
    }
    return REQUEST_CONNECTING;
}

unsigned fillRequestAnswerWithState(TSelectorKey* key, int state){
    TReqParser p = ATTACHMENT(key)->client.reqParser;
    if(state >= 0){
        p.state = state;
    }
    if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillRequestAnswer(&p, &ATTACHMENT(key)->originBuffer)){
        return ERROR;
    }
    return REQUEST_WRITE;
}

unsigned requestWrite(TSelectorKey* key) {
    TClientData* data = ATTACHMENT(key);

    size_t writeLimit;    // how many bytes we want to send
    ssize_t writeCount;   // how many bytes where written
    uint8_t* writeBuffer; // buffer that stores the data to be sended

    writeBuffer = buffer_read_ptr(&data->originBuffer, &writeLimit);
    writeCount = send(data->client_fd, writeBuffer, writeLimit, MSG_NOSIGNAL);

    if (writeCount < 0) {
        log(LOG_ERROR,"send() at fd %d", key->fd);
        return ERROR;
    }
    if (writeCount == 0) {
        log(LOG_ERROR,"Failed to send(), client closed connection unexpectedly at fd %d", key->fd);
        return ERROR;
    }
    log(DEBUG,"[Req write: INF]  %ld bytes to client %d ", writeCount, key->fd);
    buffer_read_adv(&data->originBuffer, writeCount);

    if (buffer_can_read(&data->originBuffer)) {
        return REQUEST_WRITE;
    }

    if (hasRequestErrors(&data->client.reqParser) || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }

    return COPY;
}
