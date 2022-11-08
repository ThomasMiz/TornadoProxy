#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>

#include "../selector.h"
#include "logger.h"


#define DEFAULT_LOG_FOLDER "./log"
#define DEFAULT_LOG_FILE (DEFAULT_LOG_FOLDER "/%02d-%02d-%04d.log")
#define DEFAULT_LOG_FILE_MAXSTRLEN 31

/** The minimum allowed length for the log writing buffer. */
#define LOG_MIN_BUFFER 0x1000 // 4 KBs
/** The maximum allowed length for the log writing buffer. */
#define LOG_MAX_BUFFER 0x400000 // 4 MBs
/** The amount of bytes to expand the log buffer by when expanding. */
#define LOG_BUFFER_GRANULARITY 0x1000 // 4 KBs
/** The maximum length a single print into the log buffer SHOULD require. */
#define LOG_BUFFER_MAX_PRINT_LENGTH 0x400 // 1 KB

#define LOG_FILE_PERMISSION_BITS 666
#define LOG_FOLDER_PERMISSION_BITS 666
#define LOG_FILE_OPEN_FLAGS (O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK)

/** The buffer where logs are buffered. */
static char* buffer = NULL;
static size_t bufferLength = 0, bufferCapacity = 0;

/** The file descriptor for writing logs to disk, or -1 if we're not doing that. */
static int logFileFd = -1;

/** The stream for writing logs to, or NULL if we're not doing that. */
static FILE* logStream = NULL;

/** Attempts to open a file for logging. Returns the fd, or -1 if failed. */
static int tryOpenLogfile(const char* logFile, struct tm tm) {
    if (logFile == NULL)
        return -1;
    
    char logfilebuf[DEFAULT_LOG_FILE_MAXSTRLEN + 1];
    
    if (logFile[0] == '\0') {
        snprintf(logfilebuf, DEFAULT_LOG_FILE_MAXSTRLEN, DEFAULT_LOG_FILE, tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900);
        logFile = logfilebuf;

        // If the default log folder isn't created, create it.
        mkdir(DEFAULT_LOG_FOLDER, LOG_FOLDER_PERMISSION_BITS);
    }

    int fd = open(logFile, LOG_FILE_OPEN_FLAGS, LOG_FILE_PERMISSION_BITS);
    if (fd < 0) {
        fprintf(stderr, "WARNING: Failed to open logging file at %s. The server will still run, but with logging disabled.", logFile);
        return -1;
    }

    return fd;

}

int logInit(TSelector selector, const char* logFile, const FILE* logStreamParam) {
    time_t T = time(NULL);
    struct tm tm = *localtime(&T);
    
    logFileFd = tryOpenLogfile(logFile, tm);
    logStream = logStreamParam;

    if (logFileFd >= 0) {
        char pipi[128];
        sprintf(pipi, "System Date is: %02d/%02d/%04d\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900);
        ssize_t written = write(logFileFd, pipi, strlen(pipi));
        printf("Written 1: %ld", written);
        sprintf(pipi, "System Time is: %02d:%02d:%02d\n", tm.tm_hour, tm.tm_min, tm.tm_sec);
        written = write(logFileFd, pipi, strlen(pipi));
        printf("Written 2: %ld", written);
    }

    return 0;
}

int logFinalize() {
    if (logFileFd >= 0) {
        close(logFileFd);
        logFileFd = -1;
    }

    logStream = NULL;
    return 0;
}

int logNewClient(int clientId, const struct sockaddr* origin, socklen_t originLength) {
    return 0;
}

int logClientDisconnected(int clientId, const char* username, const char* reason) {
    return 0;
}

int logClientAuthenticated(int clientId, const char* username, int successful) {
    return 0;
}

int logClientConnectionRequestAddress(int clientId, const char* username, const struct sockaddr* remote, socklen_t remoteLength) {
    return 0;
}

int logClientConnectionRequestDomainname(int clientId, const char* username, const char* domainname) {
    return 0;
}

int logClientConnectionRequestAttempt(int clientId, const char* username, const struct sockaddr* remote, socklen_t remoteLength) {
    return 0;
}

int logClientConnectionRequestSuccess(int clientId, const char* username, const struct sockaddr* remote, socklen_t remoteLength) {
    return 0;
}

int logClientBytesTransfered(int clientId, const char* username, size_t bytesSent, size_t bytesReceived) {
    return 0;
}