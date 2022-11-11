#ifndef MGMT_H
#define MGMT_h

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "selector.h"
#include "buffer.h"


#define CLIENT_MGMT_BUFFER_SIZE 4096

void mgmt_passive_accept_handler(TSelectorKey *key);

#endif