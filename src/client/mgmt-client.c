#include "mgmt-client-utils.h"
#include <stdint.h>
#include "mgmtClientCommands.h"

#define SERVER "localhost" 
#define PORT "8080"

int main(int argc, char *argv[]) {

    if (argc <= 1) {
        printf("Usage: %s <command> <arguments>\n", argv[0]);
        return -1;
    }
    
    if (strcmp("-h", argv[1]) == 0) {
        printf("ha\n");
            fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h                                 Imprime la ayuda y termina.\n" 
            "   USERS                              Envía un pedido para obtener los usuarios registrados.\n" 
            "   ADD-USER <username> <password>     Envía un pedido para agregar un usuario al registro del servidor.\n"
            "   DELETE-USER <username>             Envía un pedido para borrar un usuario del registro del servidor.\n"
            "   GET-DISSECTOR-STATUS               Envía un pedido para obtener el estado del disector de contraseñas.\n"
            "   SET-DISSECTOR-STATUS [ON/OFF]      Envía un pedido para setear el estado del disector de contraseñas.\n"
            "   STATISTICS                         Envía un pedido de las estadísticas del servidor.\n"
            "\n","client");
            return 0;
    }

    char *command = argv[1];
    int commandReference;

    if(!commandExists(command, &commandReference)){
        printf("%s: is not a valid command\n", command);
        return -1;
    }

    if(!argsQuantityOk(commandReference, argc)){
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
        status = cmdAddUser(sock, commandReference, argv[2], argv[3]);
            break;
        case CMD_DELETE_USER:
        status = cmdDeleteUser(sock, commandReference, argv[2]);
            break;
        case CMD_GET_DISSECTOR_STATUS:
        status = cmdGetDissectorStatus(sock, commandReference);
            break;
        case CMD_SET_DISSECTOR_STATUS:
        status = cmdSetDissectorStatus(sock, commandReference, argv[2]);
            break;
        case CMD_STATS:
        status = cmdStats(sock, commandReference);
            break;
        default: 
            return -1;
    }

    if (status) {
        printf("error sending command\n");
        return -1;
    }

    uint8_t c;
    int qty;
    bool readCarriageReturn = false;
    while ((qty = read(sock, &c, 1)) > 0 && !(readCarriageReturn && c == '\n')) {
        if (qty < 0) {
            printf("error reading from server\n");
            return -1;
        }
        putchar(c);

        readCarriageReturn = c == '\r';
    }

    putchar('\n');

    return 0;
}