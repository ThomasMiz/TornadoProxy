// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "mgmtClientCommands.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#define ON "ON"
#define OFF "OFF"
#define BUFFER_SIZE 256

enum DissectorStatus {
    OFF_CODE = 0,
    ON_CODE
};

static int sendByte(int sock, int cmd) {
    return (send(sock, &cmd, 1, 0) != 1);
}

static int sendString(int sock, char* s) {
    int len = strlen(s);

    if (send(sock, &len, 1, 0) < 1) {
        return -1;
    }

    if (send(sock, s, len, 0) <= 0) {
        return -1;
    }
    return 0;
}

static int setStatusGenericCmd(int sock, int cmdValue, char* status) {
    if (sendByte(sock, cmdValue)) {
        printf("error sending command\n");
        return -1;
    }

    if (strcasecmp(ON, status) == 0) {
        if (sendByte(sock, ON_CODE)) {
            printf("error sending ON status\n");
            return -1;
        }
    } else if (strcasecmp(OFF, status) == 0) {
        if (sendByte(sock, OFF_CODE)) {
            printf("error sending OFF status\n");
            return -1;
        }
    } else {
        printf("invalid status value %s\n", status);
        return -1;
    }

    return 0;
}

static int sendUserInfoCmd(int sock, int cmdValue, char* username, char* password, char* role) {

    if (sendByte(sock, cmdValue)) {
        printf("error sending command\n");
        return -1;
    }

    if (username != NULL && sendString(sock, username)) {
        printf("error sending username string\n");
        return -1;
    }

    if (password != NULL && sendString(sock, password)) {
        printf("error sending password string\n");
        return -1;
    }

    if (role != NULL) {
        int roleToInt = (*role) - '0';
        if (sendByte(sock, roleToInt)) {
            printf("error sending role string\n");
            return -1;
        }
    }
    return 0;
}

int cmdUsers(int sock, int cmdValue) {
    return sendByte(sock, cmdValue);
}

int cmdStats(int sock, int cmdValue) {
    return sendByte(sock, cmdValue);
}

int cmdAddUser(int sock, int cmdValue, char* username, char* password, char* role) {
    return sendUserInfoCmd(sock, cmdValue, username, password, role);
}

int cmdDeleteUser(int sock, int cmdValue, char* username) {
    return sendUserInfoCmd(sock, cmdValue, username, NULL, NULL);
}

int cmdChangePassword(int sock, int cmdValue, char* username, char* password) {
    return sendUserInfoCmd(sock, cmdValue, username, password, NULL);
}

int cmdChangeRole(int sock, int cmdValue, char* username, char* role) {
    return sendUserInfoCmd(sock, cmdValue, username, NULL, role);
}

int cmdGetDissectorStatus(int sock, int cmdValue) {
    return sendByte(sock, cmdValue);
}

int cmdSetDissectorStatus(int sock, int cmdValue, char* status) {
    return setStatusGenericCmd(sock, cmdValue, status);
}

int cmdGetAuthenticationStatus(int sock, int cmdValue) {
    return sendByte(sock, cmdValue);
}

int cmdSetAuthenticationStatus(int sock, int cmdValue, char* status) {
    return setStatusGenericCmd(sock, cmdValue, status);
}
