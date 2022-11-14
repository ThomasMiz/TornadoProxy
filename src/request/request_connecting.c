#include "../selector.h"
#include "../socks5.h"
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include "request_connecting.h"
#include "request.h"
#include "../netutils.h"
#include "../logger.h"

void request_connecting_init(const unsigned state, TSelectorKey* key) {
    TClientData* d = ATTACHMENT(key);
    TFdInterests curr_interests;
    selector_get_interests_key(key, &curr_interests);
    selector_set_interest(key->s, d->client_fd, OP_WRITE);
    log(DEBUG, "[Req con: init] ended for fd: %d", key->fd);
}

unsigned request_connecting(TSelectorKey* key) {
    TClientData* d = ATTACHMENT(key);
    TFdInterests curr_interests;
    selector_get_interests_key(key, &curr_interests);

    log(DEBUG, "[Req con: request_connecting] started for fd: %d", key->fd);

    if (d->client_fd == key->fd) // Se llama primero al handler del cliente, y entonces nos conectamos al OS
    {
        //TODO: Consider looping throw all the possible addresses given
        selector_set_interest(key->s, d->client_fd, INTEREST_OFF(curr_interests, OP_WRITE));
        assert(d->origin_resolution != NULL);
        d->origin_fd = socket(d->origin_resolution->ai_family, SOCK_STREAM | SOCK_NONBLOCK, d->origin_resolution->ai_protocol);
        if (d->origin_fd >= 0) {
            selector_fd_set_nio(d->origin_fd);
            char address_buf[1024];
            sockaddr_to_human(address_buf, 1024, d->origin_resolution->ai_addr);
            printf("Connecting to %s\n", address_buf);
            if ( connect(d->origin_fd, d->origin_resolution->ai_addr, d->origin_resolution->ai_addrlen) == 0 || errno == EINPROGRESS) {
                // Registramos al FD del OS con OP_WRITE y la misma state machine, entonces esperamos a que se corra el handler para REQUEST_CONNECTING del lado del OS
                if (selector_register(key->s, d->origin_fd, get_state_handler(), OP_WRITE, d) != SELECTOR_SUCCESS) {
                    return ERROR;
                }
                return REQUEST_CONNECTING;
            }
            //ECONNREFUSED  A connect() on a stream socket found no one listening on the remote address.
            //ENETUNREACH   Network is unreachable.
            //ETIMEDOUT
        }
        //General server failure
        return ERROR;
    }

    // Ya nos conectamos (handler del lado del OS)
    char buf[BUFFER_SIZE];
    sockaddr_to_human(buf, BUFFER_SIZE, d->origin_resolution->ai_addr);
    log(DEBUG, "Checking connection status to %s", buf);

    int error = 0;
    if (getsockopt(d->origin_fd, SOL_SOCKET, SO_ERROR, &error,&(socklen_t){sizeof(int)})) {
        return fillRequestAnswerWithState(key, REQ_ERROR_GENERAL_FAILURE);
    }

    if (error) {
        return fillRequestAnswerWithState(key, REQ_ERROR_GENERAL_FAILURE);
    }

    selector_set_interest(key->s, d->origin_fd, OP_READ);
    selector_set_interest(key->s, d->client_fd, OP_READ);
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillRequestAnswer(&d->client.reqParser, &d->originBuffer)) {
        return ERROR;
    }
    return REQUEST_WRITE;
}
