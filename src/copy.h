
#ifndef COPY_H
#define COPY_H
#include "socks5.h"
unsigned socksv5_handle_read(TSelectorKey* key);
unsigned socksv5_handle_write(TSelectorKey* key);
void socksv5_handle_close(const unsigned int state, TSelectorKey* key);

#endif