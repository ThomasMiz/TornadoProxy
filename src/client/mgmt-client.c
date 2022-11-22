// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com


#include "mgmt-client-utils.h"
#include "mgmtClientCommands.h"
#include <stdint.h>

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT "8080"

int main(int argc, char* argv[]) {
    if (argc <= 3 || strcmp("-h", argv[3]) == 0) {
        fprintf(stderr,
                "Usage: %s [HOST] [PORT] [OPTION]...\n"
                "\n [HOST] and [PORT] may be specified as '-' to use defaults."
                "\n"
                "   -h                                        Prints help and finish.\n"
                "   USERS                                     Submits a request to get registered users.\n"
                "   ADD-USER <username> <password> <role>     Sends a request to add a user to the server.\n"
                "   DELETE-USER <username>                    Sends a request to delete a user from the server.\n"
                "   CHANGE-PASSWORD <username> <password>     Sends a request to update the user's password.\n"
                "   CHANGE-ROLE <username> <role>             Submits a request to update the user's role.\n"
                "   GET-DISSECTOR-STATUS                      Submits a request to get the status of the password dissector.\n"
                "   SET-DISSECTOR-STATUS [ON/OFF]             Sends a request to set the state of the password dissector.\n"
                "   GET-AUTHENTICATION-STATUS                 Sends a request to get the status of the sock's authentication level.\n"
                "   SET-AUTHENTICATION-STATUS [ON/OFF]        Sends a request to set the state of the sock's authentication level.\n"
                "   STATISTICS                                Sends a request to get specific metrics from the server.\n"
                "\n",
                argv[0]);
        return 0;
    }

    const char* host = argv[1];
    const char* port = argv[2];

    if (host[0] == '-')
        host = DEFAULT_HOST;
    if (port[0] == '-')
        port = DEFAULT_PORT;


    char* command = argv[3];
    int commandReference;

    if (!commandExists(command, &commandReference)) {
        printf("%s: is not a valid command\n", command);
        return -1;
    }

    if (!argsQuantityOk(commandReference, argc)) {
        printf("%s: few arguments\n", command);
        return -1;
    }

    char* token = getenv("TOKEN");

    if (token == NULL) {
        printf("No token provided for connection\n");
        return -1;
    }

    if (!validToken(token)) {
        printf("Token contains non printable characters\n");
        return -1;
    }

    char* username = strtok(token, ":");

    if (username == NULL) {
        printf("Invalid username format\n");
        return -1;
    }
    char* password = strtok(NULL, ":");

    if (password == NULL) {
        printf("Invalid password format\n");
        return -1;
    }
    char* role = commandReference == CMD_ADD_USER ? argv[6] : (commandReference == CMD_CHANGE_ROLE ? argv[5] : NULL);
    if (role != NULL) {
        int len = strlen(role);
        if (len != 1) {
            printf("Invalid role format, must be a digit\n");
            return -1;
        }

        if (!isdigit((*role))) {
            printf("Invalid role format, must be a digit\n");
            return -1;
        }
    }

    int sock = tcpClientSocket(host, port);
    if (sock < 0) {
        perror("socket() failed");
        return -1;
    }

    if (!authenticate(username, password, sock)) {
        return closeConnection("Error authenticating with the server", sock);
    }

    int status;
    switch (commandReference) {
        case CMD_USERS:
            status = cmdUsers(sock, commandReference);
            break;
        case CMD_ADD_USER:
            status = cmdAddUser(sock, commandReference, argv[4], argv[5], argv[6]);
            break;
        case CMD_DELETE_USER:
            status = cmdDeleteUser(sock, commandReference, argv[4]);
            break;
        case CMD_CHANGE_PASSWORD:
            status = cmdChangePassword(sock, commandReference, argv[4], argv[5]);
            break;
        case CMD_CHANGE_ROLE:
            status = cmdChangeRole(sock, commandReference, argv[4], argv[5]);
            break;
        case CMD_GET_DISSECTOR_STATUS:
            status = cmdGetDissectorStatus(sock, commandReference);
            break;
        case CMD_SET_DISSECTOR_STATUS:
            status = cmdSetDissectorStatus(sock, commandReference, argv[4]);
            break;
        case CMD_GET_AUTHENTICATION_STATUS:
            status = cmdGetAuthenticationStatus(sock, commandReference);
            break;
        case CMD_SET_AUTHENTICATION_STATUS:
            status = cmdSetAuthenticationStatus(sock, commandReference, argv[4]);
            break;
        case CMD_STATS:
            status = cmdStats(sock, commandReference);
            break;
        default:
            return -1;
    }

    if (status) {
        return closeConnection("Error sending command\n", sock);
    }

    uint8_t c;
    int qty;
    bool readCarriageReturn = false;
    while ((qty = read(sock, &c, 1)) > 0 && !(readCarriageReturn && c == '\n')) {
        putchar(c);
        readCarriageReturn = c == '\r';
    }

    putchar('\n');
    close(sock);
    return 0;
}
