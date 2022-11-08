#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>

#include "../selector.h"
#include "logger.h"

#define DEFAULT_LOG_FOLDER "./log"
#define DEFAULT_LOG_FILE (DEFAULT_LOG_FOLDER "/%02d-%02d-%04d.log")
#define DEFAULT_LOG_FILE_MAXSTRLEN 31

/** The minimum allowed length for the log writing buffer. */
#define LOG_MIN_BUFFER_SIZE 0x1000 // 4 KBs
/** The maximum allowed length for the log writing buffer. */
#define LOG_MAX_BUFFER_SIZE 0x400000 // 4 MBs
/** The amount of bytes to expand the log buffer by when expanding. */
#define LOG_BUFFER_SIZE_GRANULARITY 0x1000 // 4 KBs
/** The maximum length a single print into the log buffer SHOULD require. */
#define LOG_BUFFER_MAX_PRINT_LENGTH 0x200 // 512 bytes

#define LOG_FILE_PERMISSION_BITS 666
#define LOG_FOLDER_PERMISSION_BITS 666
#define LOG_FILE_OPEN_FLAGS (O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK)

#define LOG_LINE_START "[%02d/%02d/%04d %02d:%02d:%02d] "
#define LOG_PRINTF_START_PARAMS tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec

/** The buffer where logs are buffered. */
static char* buffer = NULL;
static size_t bufferStart = 0, bufferLength = 0, bufferCapacity = 0;

/** The file descriptor for writing logs to disk, or -1 if we're not doing that. */
static int logFileFd = -1;
static TSelector selector = NULL;

static inline void tryFlushBufferToFile() {
    // Try to write everything we have in the buffer. This is nonblocking, so any
    // (or all) remaining bytes will be saved in the buffer and retried later.
    ssize_t written = write(logFileFd, buffer + bufferStart, bufferLength);
    if (written > 0) {
        bufferLength -= written;
        bufferStart = (bufferLength == 0 ? 0 : (bufferStart + written));
    }

    // If there are still remaining bytes to write, leave them in the buffer and retry
    // once the selector says the fd can be written.
    selector_set_interest(selector, logFileFd, bufferLength > 0 ? OP_WRITE : OP_NOOP);
}

static void fdWriteHandler(TSelectorKey* key) {
    tryFlushBufferToFile();
}

static void fdCloseHandler(TSelectorKey* key) {
    // We will attempt to flush the remaining bytes to the log file and then close it.

    if (bufferLength != 0) {
        // Set the log file to blocking, then try to write the remaining bytes. If any of
        // this fails, just ignore the failure.
        int flags = fcntl(logFileFd, F_GETFD, 0);
        int pepe = fcntl(logFileFd, F_SETFL, flags & (~O_NONBLOCK));
        fprintf(stderr, "Pedro y Pepe: %d y %d\n", flags, pepe); // TODO: remove lol
        ssize_t written = write(logFileFd, buffer, bufferLength);
        if (written > 0) {
            bufferLength -= written;
            bufferStart = (bufferLength == 0 ? 0 : (bufferStart + written));
        }
    }

    close(logFileFd);
    logFileFd = -1;
}

static TFdHandler fdHandler = {
    .handle_read = NULL,
    .handle_write = fdWriteHandler,
    .handle_close = fdCloseHandler,
    .handle_block = NULL};

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

int logInit(TSelector selectorParam, const char* logFile, FILE* logStreamParam) {
    time_t T = time(NULL);
    struct tm tm = *localtime(&T);

    selector = selectorParam;
    logFileFd = selectorParam == NULL ? -1 : tryOpenLogfile(logFile, tm);
    logStream = logStreamParam;

    if (logFileFd >= 0) {
        selector_register(selector, logFileFd, &fdHandler, OP_NOOP, NULL);
        buffer = malloc(LOG_MIN_BUFFER_SIZE);
        bufferCapacity = LOG_MIN_BUFFER_SIZE;
        bufferLength = 0;
        bufferStart = 0;
        if (buffer == NULL) {
            close(logFileFd);
            logFileFd = -1;
            fprintf(stderr, "WARNING: Failed to malloc a buffer for logging. How do you not have 4KBs?? 😡😡\n");
            return -1;
        }
    }


    logRawString("pedro XD");

    return 0;
}

int logFinalize() {
    if (logFileFd >= 0) {
        selector_unregister_fd(selector, logFileFd); // This will also close the TFdHandler's close, and close the file.
        selector = NULL;
    }

    if (buffer != NULL) {
        free(buffer);
        buffer = NULL;
        bufferCapacity = 0;
        bufferLength = 0;
        bufferStart = 0;
    }

    logStream = NULL;
    return 0;
}

int logRawString(const char* s) {
    size_t len = strlen(s);

    // Make enough space in the buffer for the string
    if (bufferLength + bufferStart + len > bufferCapacity) {
        // If the buffer can be compacted to fit this string, do so. Otherwise,
        // we'll have to allocate more memory.
        if (bufferCapacity <= len) {
            memmove(buffer, buffer + bufferStart, bufferLength);
            bufferStart = 0;
        } else if (bufferCapacity < LOG_MAX_BUFFER_SIZE) {
            size_t newBufferCapacity = bufferLength + len;
            newBufferCapacity = (newBufferCapacity + LOG_BUFFER_SIZE_GRANULARITY - 1) / LOG_BUFFER_SIZE_GRANULARITY * LOG_BUFFER_SIZE_GRANULARITY;
            if (newBufferCapacity > LOG_MAX_BUFFER_SIZE)
                newBufferCapacity = LOG_MAX_BUFFER_SIZE;

            void* newBuffer = malloc(newBufferCapacity);
            if (newBuffer == NULL) {
                memmove(buffer, buffer + bufferStart, bufferLength);
                bufferStart = 0;
            } else {
                memcpy(newBuffer, buffer + bufferStart, bufferLength);
                free(buffer);
                buffer = newBuffer;
                bufferCapacity = newBufferCapacity;
                bufferStart = 0;
            }
        }
    }

    time_t T = time(NULL);
    struct tm tm = *localtime(&T);
    size_t maxlen = bufferCapacity - bufferLength - bufferStart;
    int written = snprintf(buffer + bufferStart, maxlen, LOG_LINE_START "%s\n", LOG_PRINTF_START_PARAMS, s);
    if (written < 0) {
        fprintf(stderr, "Error: snprintf(): %s", strerror(errno));        
    } else if (written >= maxlen) {
        fprintf(stderr, "Error: %ld bytes of logs possibly lost due to slow disk.\n", written - maxlen + 1);
        written = maxlen - 1;
    }
    bufferLength += written;
    tryFlushBufferToFile();
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