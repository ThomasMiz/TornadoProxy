#include "copy.h"

unsigned socksv5_handle_read(TSelectorKey* key) {
    TClientData* clientData = key->data;
    buffer* client_buffer = &clientData->client_buffer;
    buffer* origin_buffer = &clientData->origin_buffer;
    int client_fd = clientData->client_fd;
    int origin_fd = clientData->origin_fd;
    char tmp_buf[BUFFER_SIZE];
    size_t capacity;
    TFdInterests curr_interests;
    selector_get_interests(key, &curr_interests);

    if (client_fd == key->fd) {
    printf("reading from fd client\n");
        if (!buffer_can_write(origin_buffer)) {
            selector_set_interest(key->s, client_fd, OP_READ | curr_interests); // revisar
            return COPY;
        }

        u_int8_t* write_ptr = buffer_write_ptr(origin_buffer, &capacity);
        if (capacity > BUFFER_SIZE)
            capacity = BUFFER_SIZE;
        ssize_t read_bytes = read(client_fd, tmp_buf, capacity);
        if (read_bytes > 0) {
            memcpy(write_ptr, tmp_buf, read_bytes);
            buffer_write_adv(origin_buffer, read_bytes);
            size_t remaining;
            buffer_read_ptr(client_buffer, &remaining);
            printf("recv() %ld bytes from client %d [remaining to read %lu]\n", read_bytes, key->fd, remaining);
            selector_set_interest(key->s, origin_fd, OP_WRITE);

        } else { // EOF or err
            printf("recv() returned %ld, closing client %d\n", read_bytes, key->fd);
            selector_unregister_fd(key->s, key->fd);
            return DONE;
        }

        TFdInterests newInterests = OP_WRITE;
        if (buffer_can_write(origin_buffer))
            newInterests |= OP_READ;


        selector_set_interest_key(key, newInterests);
    } else { // fd == origin_fd
    printf("reading from fd origin\n");
        if (!buffer_can_write(client_buffer)) {
            selector_set_interest(key->s, origin_fd, OP_READ | curr_interests);
            return COPY;
        }

        uint8_t* write_ptr = buffer_write_ptr(client_buffer, &capacity);
        if (capacity > BUFFER_SIZE)
            capacity = BUFFER_SIZE;
        ssize_t read_bytes = read(origin_fd, tmp_buf, capacity);
        if (read_bytes > 0) {
            memcpy(write_ptr, tmp_buf, read_bytes);
            buffer_write_adv(client_buffer, read_bytes);
            size_t remaining;
            buffer_read_ptr(origin_buffer, &remaining);
            printf("recv() %ld bytes from origin %d [remaining to read %lu]\n", read_bytes, key->fd, remaining);
            selector_set_interest(key->s, client_fd, OP_WRITE);

        } else { // EOF
            printf("recv() returned %ld, closing origin %d\n", read_bytes, key->fd);
            selector_unregister_fd(key->s, key->fd);
            return DONE;
        }

        TFdInterests newInterests = OP_WRITE;
        if (buffer_can_write(client_buffer))
            newInterests |= OP_READ;

        selector_set_interest(key->s, client_fd, newInterests);
    }
    return COPY;
}

unsigned socksv5_handle_write(TSelectorKey* key) {
    TClientData* clientData = key->data;
    buffer* client_buffer = &clientData->client_buffer;
    buffer* origin_buffer = &clientData->origin_buffer;
    int client_fd = clientData->client_fd;
    int origin_fd = clientData->origin_fd;
    size_t capacity;
    TFdInterests curr_interests;
    selector_get_interests(key, &curr_interests);
    // Try to send as many of the bytes as we have in the buffer.
    if (key->fd == client_fd) {
        printf("writing to client\n");
        if (!buffer_can_read(client_buffer)) {
            selector_set_interest_key(key, INTEREST_OFF(curr_interests,OP_WRITE));
            printf("copy\n");
            return COPY;
        }
        uint8_t* read_ptr = buffer_read_ptr(client_buffer, &capacity);
        ssize_t sent = send(client_fd, read_ptr, capacity, 0); // habia que usar algun flag?
        if (sent <= 0) {
            printf("send() returned %ld, closing client %d\n", sent, key->fd);
            selector_unregister_fd(key->s, key->fd);
            return DONE;
        }
        buffer_read_adv(client_buffer, sent);

        printf("send() %ld bytes to client %d [%lu remaining]\n", sent, key->fd, capacity - sent);

        // Calculate the new interests for this socket. We want to read, and possibly write if we still have more buffer data.
        TFdInterests newInterests = OP_READ;
        if (buffer_can_read(client_buffer))
            newInterests |= OP_WRITE;

        // Update the interests in the selector.
        selector_set_interest_key(key, newInterests);
    } else {
        printf("writing to origin\n");

        if (!buffer_can_read(origin_buffer)) {
            selector_set_interest_key(key, INTEREST_OFF(curr_interests,OP_WRITE));
            return COPY;
        }
        uint8_t* read_ptr = buffer_read_ptr(origin_buffer, &capacity);
        ssize_t sent = send(origin_fd, read_ptr, capacity, 0);
        if (sent <= 0) {
            printf("send() returned %ld, closing origin %d\n", sent, key->fd);
            selector_unregister_fd(key->s, key->fd);
            return DONE;
        }
        buffer_read_adv(origin_buffer, sent);

        printf("send() %ld bytes to origin %d [%lu remaining]\n", sent, key->fd, capacity - sent);

        // Calculate the new interests for this socket. We want to read, and possibly write if we still have more buffer data.
        TFdInterests newInterests = OP_READ;
        if (buffer_can_read(origin_buffer))
            newInterests |= OP_WRITE;

        // Update the interests in the selector.
        selector_set_interest(key->s,origin_fd,newInterests);
    }

    return COPY;
}

void socksv5_handle_close(const unsigned int state, TSelectorKey* key) {
    TClientData* clientData = key->data;

    // Free the memory associated with this client.
    if (clientData != NULL) {
        if (clientData->origin_resolution != NULL)
            freeaddrinfo(clientData->origin_resolution);
        free(clientData);
    }

    // Close the socket file descriptor associated with this client.
    close(key->fd);

    printf("Client closed: %d\n", key->fd);
}