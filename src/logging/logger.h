#ifndef _LOGGER_H_
#define _LOGGER_H_

// The logger makes copies of any data it needs from pointer parameters in the functions
// described in this file. aka "Don't worry about the memory lifecycle of pointer parameters".

// Define this to fully disable all loggin on compilation.
//#define DISABLE_LOGGER

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <time.h>

#include "../selector.h"

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3,
    LOG_FATAL = 4
} TLogLevel;

#define MIN_LOG_LEVEL LOG_DEBUG
#define MAX_LOG_LEVEL LOG_FATAL

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
int loggerInit(TSelector selector, const char* logFile, FILE* logStream);

/**
 * @brief Closes the logging system, flushing any remaining logs, closing any opened
 * files and unregistering them from the selector.
 */
int loggerFinalize();

void loggerSetLevel(TLogLevel level);

const char* loggerGetLevelString(TLogLevel level);

int loggerIsEnabledFor(TLogLevel level);

#ifdef DISABLE_LOGGER
#define logf(level, format, ...)
#else
void loggerPrePrint();

void loggerGetBufstartAndMaxlength(char** bufstartVar, size_t* maxlenVar);

int loggerPostPrint(int written, size_t maxlen);

#define logf(level, format, ...)                                                                                                          \
    if (loggerIsEnabledFor(level)) {                                                                                                      \
        loggerPrePrint();                                                                                                                 \
        time_t loginternal_time = time(NULL);                                                                                             \
        struct tm loginternal_tm = *localtime(&loginternal_time);                                                                         \
        size_t loginternal_maxlen;                                                                                                        \
        char* loginternal_bufstart;                                                                                                       \
        loggerGetBufstartAndMaxlength(&loginternal_bufstart, &loginternal_maxlen);                                                        \
        int loginternal_written = snprintf(loginternal_bufstart, loginternal_maxlen, "[%02d/%02d/%04d %02d:%02d:%02d] [%s] " format "\n", \
                                           loginternal_tm.tm_mday, loginternal_tm.tm_mon + 1, loginternal_tm.tm_year + 1900,              \
                                           loginternal_tm.tm_hour, loginternal_tm.tm_min, loginternal_tm.tm_sec,                          \
                                           loggerGetLevelString(level), ##__VA_ARGS__);                                                   \
        loggerPostPrint(loginternal_written, loginternal_maxlen);                                                                         \
    }
#endif

#define log(level, s) logf(level, "%s", s)

/**
 * @brief Log that the server has opened a socket listening at the specified socekt.
 * @param listenSocket The address the server socket is bound to, or NULL if unknown.
 * @param listenSocketLen The length of the socket address specified in listenSocket.
 */
void logServerListening(const struct sockaddr* listenAddress, socklen_t listenAddressLen);

/**
 * @brief Log that a client connection has disconnected. This should be called as soon
 * as the TCP connection is closed.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param username The client's username, or null if not logged in.
 * @param reason A human-readable string indicating why the client was disconnected.
 * For example, "connection closed by client", "no valid auth method", "solar storm"
 */
void logClientDisconnected(int clientId, const char* username, const char* reason);

/**
 * @brief Log that a client attempted to authenticate, whether successfull or not.
 * This should be called after the user chose an authentication method and attempted it.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param user The username specified, or null if not loggin in with username.
 * @param successful Whether the authentication was successful.
 */
void logClientAuthenticated(int clientId, const char* username, int successful);

/**
 * @brief Log that the server is attempting to establish a connection requested by a
 * client.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param username The client's username, or null if not logged in.
 * @param remote The address the server is attempting to connect to.
 * @param remoteLength The length of the address specified in remote.
 */
void logClientConnectionRequestAttempt(int clientId, const char* username, const struct sockaddr* remote, socklen_t remoteLength);

/**
 * @brief Log that the server has successfully established a connection requested by
 * a client.
 * @param clientId The client's ID (it's socket's file descriptor).
 * @param username The client's username, or null if not logged in.
 * @param remote The address the server has to connect to.
 * @param remoteLength The length of the address specified in remote.
 */
void logClientConnectionRequestSuccess(int clientId, const char* username, const struct sockaddr* remote, socklen_t remoteLength);

#endif