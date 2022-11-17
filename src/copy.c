#include "copy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "logger.h"
#include "socks5.h"

#define CLIENT_NAME "client"
#define ORIGIN_NAME "origin"

static TFdInterests copy_compute_interests(TSelector s, TCopy * copy) {
    TFdInterests ret = OP_NOOP;
    if ((copy->duplex & OP_READ) && buffer_can_write(copy->otherBuffer)) {
        ret |= OP_READ;
    }
    if ((copy->duplex & OP_WRITE) && buffer_can_read(copy->targetBUffer)) {
        ret |= OP_WRITE;
    }
    if (SELECTOR_SUCCESS != selector_set_interest(s, *copy->targetFd, ret)) {
        abort();
    }
    return ret;
}

unsigned copy_read_handler(TClientData* clientData, TCopy * copy) {
    int target_fd = *copy->targetFd;
    int other_fd = *copy->otherFd;
    TSelector s = copy->s;
    buffer * other_buffer = copy->otherBuffer;
    char * name = copy->name;
    log(DEBUG, "[Copy: copy_read_handler] reading from fd %s %d", name, target_fd);
    size_t capacity;
    size_t remaining;

    if (!buffer_can_write(other_buffer)) {
        return COPY;
    }

    u_int8_t* write_ptr = buffer_write_ptr(other_buffer, &(capacity));

    if (capacity > BUFFER_SIZE)
        capacity = BUFFER_SIZE;
    ssize_t read_bytes = recv(target_fd, write_ptr, capacity, 0);

    if (read_bytes > 0) {
        //memcpy(write_ptr, tmp_buf, read_bytes);
        buffer_write_adv(other_buffer, read_bytes);
        buffer_write_ptr(other_buffer, &(remaining));
        log(DEBUG, "recv() %ld bytes from %s %d [remaining buffer capacity %lu]", read_bytes, name, target_fd, remaining);

        if(clientData->pDissector.isOn){
            parseUserData(&clientData->pDissector, other_buffer, target_fd);
        }
    }

    else { // EOF or err
        log(DEBUG, "recv() returned %ld, closing %s %d", read_bytes, name, target_fd);
        //selector_unregister_fd(s, target_fd);
        shutdown(target_fd, SHUT_RD);
        copy->duplex &= ~OP_READ;
        if (other_fd != -1) {
            shutdown(*(copy->otherFd), SHUT_WR);
            *(copy->otherDuplex) &= ~OP_WRITE;
        }
    }

    copy_compute_interests(s,copy);
    copy_compute_interests(s,copy->otherCopy);
    if(copy->duplex == OP_NOOP ){
        return DONE;
    }
    return COPY;
}

unsigned copy_write_handler(TCopy * copy) {
    // TFdInterests curr_interests;
    int target_fd = *copy->targetFd;
    TSelector s = copy->s;
    buffer * target_buffer = copy->targetBUffer;
    char * name = copy->name;

    log(DEBUG, "[Copy: copy_read_handler] writing to fd %s %d", name, target_fd);

    // selector_get_interests(s, target_fd, &curr_interests);
    size_t capacity;
    ssize_t sent;
    if (!buffer_can_read(target_buffer)) {
        // selector_set_interest(s, target_fd, INTEREST_OFF(curr_interests, OP_WRITE));
        return COPY;
    }
    uint8_t* read_ptr = buffer_read_ptr(target_buffer, &(capacity));
    sent = send(target_fd, read_ptr, capacity, MSG_NOSIGNAL);
    if (sent <= 0) {
        log(DEBUG, "send() returned %ld, closing %s %d", sent, name, target_fd);
        selector_unregister_fd(s, target_fd);
        return DONE;
    } else if (sent < 0) {
        shutdown(*(copy->targetFd), SHUT_WR);
        copy->duplex &= ~OP_WRITE;
        if (*(copy->otherFd) != -1) {
            shutdown(*(copy->otherFd), SHUT_RD);
            *(copy->otherDuplex) &= ~OP_READ;
        }
    } else {
        buffer_read_adv(target_buffer, sent);
    }

    log(DEBUG, "send() %ld bytes to %s %d [%lu remaining]", sent, name, target_fd, capacity - sent);
    copy_compute_interests(s,copy);
    copy_compute_interests(s,copy->otherCopy);
    return COPY;
}

void socksv5HandleInit(const unsigned int st, TSelectorKey* key) {
    TClientData* data = ATTACHMENT(key);
    TConnection * connections = &(data->connections);
    int * client_fd = &data->clientFd;
    int * origin_fd = &data->originFd;
    TCopy* client_copy = &(connections->clientCopy);
    client_copy->targetFd = client_fd;
    client_copy->otherFd = origin_fd;
    client_copy->targetBUffer = &data->clientBuffer;
    client_copy->otherBuffer = &data->originBuffer;
    client_copy->name = CLIENT_NAME;
    client_copy->s = key->s;
    client_copy->duplex = OP_READ | OP_WRITE;

    TCopy* origin_copy = &(connections->originCopy);
    origin_copy->targetFd = origin_fd;
    origin_copy->otherFd = client_fd;
    origin_copy->targetBUffer = &data->originBuffer;
    origin_copy->otherBuffer = &data->clientBuffer;
    origin_copy->name = ORIGIN_NAME;
    origin_copy->s = key->s;
    origin_copy->duplex = OP_READ | OP_WRITE;

    client_copy->otherDuplex = &(origin_copy->duplex);
    client_copy->otherCopy = &(connections->originCopy);
    origin_copy->otherDuplex = &(client_copy->duplex);
    origin_copy->otherCopy = &(connections->clientCopy);

    initPDissector(&data->pDissector, data->client.reqParser.port, data->clientFd, data->originFd);
}
unsigned socksv5HandleRead(TSelectorKey* key) {
    log(DEBUG, "[Copy: socksv5_handle_read] reading from fd %d", key->fd);
    TClientData* clientData = key->data;
    TConnection* connections = &(clientData->connections);
    TCopy * copy;
    if (clientData->clientFd == key->fd) {
        copy = &(connections->clientCopy);
    } else { // fd == origin_fd
        copy = &(connections->originCopy);
    }
    return copy_read_handler(clientData, copy);
}

unsigned socksv5HandleWrite(TSelectorKey* key) {
    log(DEBUG, "[Copy: socksv5_handle_write] writing to fd %d", key->fd);
    TClientData* clientData = key->data;
    TConnection* connections = &(clientData->connections);
    TCopy * copy;
    if (clientData->clientFd == key->fd) {
        copy = &(connections->clientCopy);
    } else { // fd == origin_fd
        copy = &(connections->originCopy);
    }
    return copy_write_handler(copy);
}

void socksv5HandleClose(const unsigned int state, TSelectorKey* key) {
    log(DEBUG,"Client closed: %d", key->fd);
}
