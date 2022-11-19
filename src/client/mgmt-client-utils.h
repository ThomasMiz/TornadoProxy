#ifndef MGMTC_UTILS
#define MGMTC_UTILS
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/**
 * @brief Handles socket creation and connection to the server.
 * @param service port to bind.
 * @param host to connect. 
 * @return socket fd on success. Else, it returns -1.
 */
int tcpClientSocket(const char* host, const char* service);

/**
 * @brief Verifies that the token does not contain unprintable characters and does not exceed the maximum.
 * 
 * @param token 
 * @return true if token is valid.
 */
bool validToken(const char* token);

/**
 * @brief Sends credentials to server and tries to authenticate
 *
 * @param username client username.
 * @param password client password.
 * @param socket socket fd.
 * @return true if the user was able to authenticate.
 */
bool authenticate(char *username, char *password, int socket);

/**
 * @brief Closes the connection with the server.
 * 
 * @param errorMessage appropiate error message.
 * @param socket socket fd. 
 * @return error status code.
 */
int closeConnection(const char* errorMessage, const int socket);


#endif