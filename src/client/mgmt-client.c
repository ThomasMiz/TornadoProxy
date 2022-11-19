#include "mgmt-client-utils.h"

#define SERVER "localhost" 
#define PORT "8080"

int main(int argc, char *argv[]){

    char *token = getenv("TOKEN");

	if(token == NULL){
        printf("No credentials provided for connection\n");
        return -1;
    }

    if(!validToken(token)){
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
    if(sock < 0){
        perror("socket() failed");
        return -1;
    }

    if(!authenticate(username, password, sock)) {
        return closeConnection("Could not authenticate in server", sock);
    }

    printf("Ok\n");

    return 0;
}