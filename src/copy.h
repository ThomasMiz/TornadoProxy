
#ifndef COPY_H
#define COPY_H
#include "selector.h"
#include "buffer.h"

typedef struct copy_t copy_t;
struct copy_t{
    buffer * other_buffer;
    buffer * target_buffer;
    //char tmp_buf[8192];
    int * target_fd;
    int * other_fd;
    TSelector s;
    char * name;
    size_t duplex;
    size_t * other_duplex;
    copy_t * other_copy;
};
typedef struct connections_t{
    copy_t client_copy;
    copy_t origin_copy;
}connections_t;


void socksv5_handle_init(const unsigned int st, TSelectorKey* key);
unsigned socksv5_handle_read(TSelectorKey* key);
unsigned socksv5_handle_write(TSelectorKey* key);
void socksv5_handle_close(const unsigned int state, TSelectorKey* key);

#endif