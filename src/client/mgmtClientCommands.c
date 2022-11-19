
#include "mgmtClientCommands.h"
#include <sys/socket.h>

int cmdUsers(int sock, int cmdValue) {
    return (send(sock, &cmdValue, 1, MSG_DONTWAIT) == 1);
}