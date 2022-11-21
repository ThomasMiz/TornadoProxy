
#ifndef MGMT_CLIENT_CMDS_H
#define MGMT_CLIENT_CMDS_H

/**
 * @brief Sends the USERS command to the server
 *
 * @param sock the established connection socket
 * @param cmdValue the value that represents the command in the protocol
 * @return 0 if there are no errors. -1 otherwise.
 */
int cmdUsers(int sock, int cmdValue);

/**
 * @brief Sends the CHANGE-ROLE command to the server
 *
 * @param sock the established connection socket
 * @param cmdValue the value that represents the command in the protocol
 * @param username the string that contains the username to be sent to the server
 * @param password the string that contains the password of the user
 * @param role the string that describes the role to be assigned to the user
 * @return 0 if there are no errors. -1 otherwise.
 */
int cmdAddUser(int sock, int cmdValue, char* username, char* password, char* role);

/**
 * @brief Sends the DELETE-USER command to the server
 *
 * @param sock the established connection socket
 * @param cmdValue the value that represents the command in the protocol
 * @param username the string that contains the username to be sent to the server
 * @return 0 if there are no errors. -1 otherwise.
 */
int cmdDeleteUser(int sock, int cmdValue, char* username);

/**
 * @brief Sends the CHANGE-ROLE command to the server
 *
 * @param sock the established connection socket
 * @param cmdValue the value that represents the command in the protocol
 * @param username the string that contains the username to be sent to the server
 * @param password the string that contains the new password
 * @return 0 if there are no errors. -1 otherwise.
 */
int cmdChangePassword(int sock, int cmdValue, char* username, char* password);

/**
 * @brief Sends the CHANGE-ROLE command to the server
 *
 * @param sock the established connection socket
 * @param cmdValue the value that represents the command in the protocol
 * @param username the string that contains the username to be sent to the server
 * @param role the string that describes the role to assign to the user
 * @return 0 if there are no errors. -1 otherwise.
 */
int cmdChangeRole(int sock, int cmdValue, char* username, char* role);

/**
 * @brief Sends the GET-AUTHENTICATION-STATUS command to the server
 *
 * @param sock the established connection socket
 * @param cmdValue the value that represents the command in the protocol
 * @return 0 if there are no errors. -1 otherwise.
 */
int cmdGetDissectorStatus(int sock, int cmdValue);

/**
 * @brief Sends the SET-DISSECTOR-STATUS command to the server
 *
 * @param sock the established connection socket
 * @param cmdValue the value that represents the command in the protocol
 * @param status the string that describes the status to send to the server
 * @return 0 if there are no errors. -1 otherwise.
 */
int cmdSetDissectorStatus(int sock, int cmdValue, char* status);

/**
 * @brief Sends the GET-AUTHENTICATION-STATUS command to the server
 *
 * @param sock the established connection socket
 * @param cmdValue the value that represents the command in the protocol
 * @return 0 if there are no errors. -1 otherwise.
 */
int cmdGetAuthenticationStatus(int sock, int cmdValue);


/**
 * @brief Sends the SET-AUTHENTICATION-STATUS command to the server
 *
 * @param sock the established connection socket
 * @param cmdValue the value that represents the command in the protocol
 * @param status the string that describes the status to send to the server
 * @return 0 if there are no errors. -1 otherwise.
 */
int cmdSetAuthenticationStatus(int sock, int cmdValue, char* status);

/**
 * @brief Sends the GET-STATISTICS command to the server
 *
 * @param sock the established connection socket
 * @param cmdValue the value that represents the command in the protocol
 * @return 0 if there are no errors. -1 otherwise.
 */
int cmdStats(int sock, int cmdValue);

#endif
