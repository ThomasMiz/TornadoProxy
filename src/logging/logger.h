#ifndef _LOGGER_H_
#define _LOGGER_H_

// The logger makes copies of any data it needs from pointer parameters in the functions
// described in this file. aka "Don't worry about the memory lifecycle of pointer parameters".

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

#include "../selector.h"

/**
 * @brief Initializes the logging system. Not calling this function will result is the
 * server running with logging disabled.
 * @param selector The selector to use. This is requried as logging is typically buffered,
 * and to make writes non-blocking writing can only occur when the file descriptor is
 * available.
 * @param file A file where logs are saved. Set to NULL to disable saving logs to a file,
 * or set to an empty string "" to use a default file name appended by the current date.
 * @param logStream A stream where logs are saved. Typically set to stdout to print logs
 * to the console. Set to NULL to disable. WARNING: Printing to this stream is done with
 * fprintf which may be blocking, halting the server. This stream is not closed by the
 * logging system.
*/
int logInit(TSelector selector, const char* logFile, FILE* logStream);

/**
 * @brief Closes the logging system, flushing any remaining logs, closing any opened
 * files and unregistering them from the selector.
*/
int logFinalize();

/**
 * @brief Log a raw string.
 * @param s The string to log. If this string is a string, then it will be kept as a
 * string. If it is null-terminated, it will stay null-terminated. If Hawaii ceases to
 * exist, the calling of this function has no effect whatsover on such unfathomable
 * facts. Our existance is meaningless against the power of the Almighty Twelve-Tounged
 * God. Mike Wazowski is blue and you can't convince me otherwise.
*/
int logString(const char* s);

/**
 * @brief Log that a new client connection has been established. This should be called
 * as soon as a TCP connection is established.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param origin The address the client is connecting from. This value is returned by
 * accept(). Null can be used to indicate unknown origin.
 * @param originLength the length of the socket address specified in origin.
*/
int logNewClient(int clientId, const struct sockaddr* origin, socklen_t originLength);

/**
 * @brief Log that a client connection has disconnected. This should be called as soon
 * as the TCP connection is closed.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param username The client's username, or null if not logged in.
 * @param reason A human-readable string indicating why the client was disconnected.
 * For example, "connection closed by client", "no valid auth method", "solar storm"
*/
int logClientDisconnected(int clientId, const char* username, const char* reason);

/**
 * @brief Log that a client attempted to authenticate, whether successfull or not.
 * This should be called after the user chose an authentication method and attempted it.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param user The username specified, or null if not loggin in with username.
 * @param successful Whether the authentication was successful.
*/
int logClientAuthenticated(int clientId, const char* username, int successful);

/**
 * @brief Log that a client requested to connect to a remote IP address.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param username The client's username, or null if not logged in.
 * @param remote The address the client requested to connec to.
 * @param remoteLength The length of the address specified in remote.
*/
int logClientConnectionRequestAddress(int clientId, const char* username, const struct sockaddr* remote, socklen_t remoteLength);

/**
 * @brief Log that a client requested to connect to a remote domain name.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param username The client's username, or null if not logged in.
 * @param domainname The domain name the client requested to connect to.
*/
int logClientConnectionRequestDomainname(int clientId, const char* username, const char* domainname);

/**
 * @brief Log that the server is attempting to establish a connection requested by a
 * client.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param username The client's username, or null if not logged in.
 * @param remote The address the server is attempting to connect to.
 * @param remoteLength The length of the address specified in remote.
*/
int logClientConnectionRequestAttempt(int clientId, const char* username, const struct sockaddr* remote, socklen_t remoteLength);

/**
 * @brief Log that the server has successfully established a connection requested by
 * a client.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param username The client's username, or null if not logged in.
 * @param remote The address the server has to connect to.
 * @param remoteLength The length of the address specified in remote.
*/
int logClientConnectionRequestSuccess(int clientId, const char* username, const struct sockaddr* remote, socklen_t remoteLength);

/**
 * @brief Log that a client sent or received a specified amount of bytes to the remote
 * server it's connected to.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param username The client's username, or null if not logged in.
 * @param bytesSent The amount of bytes sent by the client to the remote server.
 * @param bytesReceived The amount of bytes sent by the remote server to the client.
*/
int logClientBytesTransfered(int clientId, const char* username, size_t bytesSent, size_t bytesReceived);

#endif