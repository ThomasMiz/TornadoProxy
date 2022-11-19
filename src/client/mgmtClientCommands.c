
#include "mgmtClientCommands.h"
#include <sys/socket.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>

#define ON "ON"
#define OFF "OFF"

enum DissectorStatus {
    OFF_CODE = 0,
    ON_CODE
};

static int sendCmd(int sock, int cmd) {
    return (send(sock, &cmd, 1, 0) != 1);
}

static int sendString(int sock, char *s) {
    int len = strlen(s);

    if (send(sock, &len, 1, 0) < 1) {
        return -1;
    }

    if (send(sock, s, len, 0) <= 0) {
        return -1;
    }
    return 0;
}

int cmdUsers(int sock, int cmdValue) {
    return sendCmd(sock, cmdValue);
}

int cmdStats(int sock, int cmdValue) {
    return sendCmd(sock, cmdValue);
}

int cmdAddUser(int sock, int cmdValue, char * username, char * password) {
    if (sendCmd(sock, cmdValue)) {
        printf("error sending command\n");
        return -1;
    }

    if (sendString(sock, username)) {
        printf("error sending username string\n");
        return -1;
    }

    if (sendString(sock, password)) {
        printf("error sending password string\n");
        return -1;
    }

    return 0;
}

int cmdDeleteUser(int sock, int cmdValue, char * username) {
    if (sendCmd(sock, cmdValue)) {
        printf("error sending command\n");
        return -1;
    }

    if (sendString(sock, username)) {
        printf("error sending string content\n");
        return -1;
    }

    return 0;
}

int cmdGetDissectorStatus(int sock, int cmdValue) {
    if (sendCmd(sock, cmdValue)) {
        printf("error sending get dissector status\n");
        return -1;
    }
    return 0;
}

int cmdSetDissectorStatus(int sock, int cmdValue, char * status) {

    if (sendCmd(sock, cmdValue)) {
        printf("error sending command\n");
        return -1;
    }

    if (strcasecmp(ON, status) == 0) {
        if (sendCmd(sock, ON_CODE)) {
            printf("error sending ON status\n");
            return -1;
        }
    } else if (strcasecmp(OFF, status) == 0) {
        if (sendCmd(sock, OFF_CODE)) {
            printf("error sending OFF status\n");
            return -1;
        }
    } else {
            printf("invalid status value %s\n", status);
            return -1;
    }

    return 0;
}

