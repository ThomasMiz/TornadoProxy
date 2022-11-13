#include "selector.h"
#include "socks5.h"
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include "request_connecting.h"
#include "netutils.h"
#include "logger.h"

void request_connecting_init(const unsigned state, TSelectorKey* key) {
    TClientData* d = ATTACHMENT(key);
    TFdInterests curr_interests;
    selector_get_interests(key, &curr_interests);
    selector_set_interest(key->s, d->client_fd, OP_WRITE);
    log(DEBUG, "[Req con: init] ended for fd: %d", key->fd);
}

unsigned request_connecting(TSelectorKey* key) {
    TClientData* d = ATTACHMENT(key);
    TFdInterests curr_interests;
    selector_get_interests(key, &curr_interests);

    log(DEBUG, "[Req con: request_connecting] started for fd: %d", key->fd);

    if (d->client_fd == key->fd) // Se llama primero al handler del cliente, y entonces nos conectamos al OS
    {
        //TODO: Consider looping throw all the possible addresses given
        selector_set_interest(key->s, d->client_fd, INTEREST_OFF(curr_interests, OP_WRITE));
        assert(d->origin_resolution != NULL);
        d->origin_fd = socket(d->origin_resolution->ai_family, d->origin_resolution->ai_socktype, d->origin_resolution->ai_protocol);
        if (d->origin_fd >= 0) {
            selector_fd_set_nio(d->origin_fd);
            char address_buf[1024];
            sockaddr_to_human(address_buf, 1024, d->origin_resolution->ai_addr);
            printf("Connecting to %s\n", address_buf);
            if (connect(d->origin_fd, d->origin_resolution->ai_addr, d->origin_resolution->ai_addrlen) == 0 || errno == EINPROGRESS) {
                if (selector_register(key->s, d->origin_fd, get_state_handler(), OP_WRITE, d) != SELECTOR_SUCCESS) { // Registramos al FD del OS con OP_WRITE y la misma state machine, entonces esperamos a que se corra el handler para REQUEST_CONNECTING del lado del OS
                    return ERROR;
                }
                return REQUEST_CONNECTING;
            }
        }
        return ERROR;
    }

    // Ya nos conectamos (handler del lado del OS)

    char buf[BUFFER_SIZE];
    sockaddr_to_human(buf, BUFFER_SIZE, d->origin_resolution->ai_addr);
    printf("Connected to %s\n", buf);
    selector_set_interest(key->s, d->origin_fd, OP_READ);
    selector_set_interest(key->s, d->client_fd, OP_READ);
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || fillRequestAnswer(&d->client.reqParser, &d->originBuffer)) {
        return ERROR;
    }
    return REQUEST_WRITE;
}
