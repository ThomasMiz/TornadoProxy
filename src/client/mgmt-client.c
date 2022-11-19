#include "mgmt-client-utils.h"
#include "buffer.h"
#include <stdint.h>
#include "mgmtClientCommands.h"

#define SERVER "localhost" 
#define PORT "8080"

int main(int argc, char *argv[]) {

    if (argc <= 1) {
        printf("Usage: %s <command> <arguments>\n", argv[0]);
        return -1;
    }

    char *command = argv[1];
    int commandReference;

    if(!commandExists(command, &commandReference)){
        printf("%s: is not a valid command\n", command);
        return -1;
    }

    if(argsQuantityOk(commandReference, argc)){
        printf("%s: few arguments\n", command);
        return -1;
    }

    char *token = getenv("TOKEN");

	if(token == NULL) {
        printf("No TOKEN provided for connection\n");
        return -1;
    }

    if(!validToken(token)) {
        printf("Token contains non printable characters\n");
        return -1;
    }
    
    char *username = strtok(token, ":");

    if (username == NULL) {
        printf("Invalid token format\n");
        return -1;
    }
    char *password = strtok(NULL, ":");

    if (password == NULL) {
        printf("Invalid token format\n");
        return -1;
    }

    int sock = tcpClientSocket(SERVER, PORT);
    if(sock < 0) {
        perror("socket() failed");
        return -1;
    }

    if(!authenticate(username, password, sock)) {
        return closeConnection("Could not authenticate in server", sock);
    }


    int status;
    switch (commandReference) {
        case CMD_USERS:
        status = cmdUsers(sock, commandReference);
            break;
        case CMD_ADD_USER: 
            break;
        case CMD_DELETE_USER:
            break;
        case CMD_GET_DISSECTOR_STATUS:
            break;
        case CMD_SET_DISSECTOR_STATUS:
            break;
        case CMD_STATS:
            break;
        default: 
            return -1;
    }

    if (status) {
        printf("error sending command\n");
        return -1;
    }

    uint8_t c;
    uint8_t qty;
    bool readCarriageReturn = false;
    while ((qty = read(socket, &c, 1)) >= 0) {
        if (qty < 0) {
            printf("error reading from server\n");
            return -1;
        }
        putchar(c);

        if (readCarriageReturn && c == '\n')
            break;

        readCarriageReturn = c == '\r';
    }

    return 0;
}