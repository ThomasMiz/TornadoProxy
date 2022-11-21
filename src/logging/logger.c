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
#include "util.h"
#include "logger.h"

#define DEFAULT_LOG_FOLDER "./log"
#define DEFAULT_LOG_FILE (DEFAULT_LOG_FOLDER "/%02d-%02d-%04d.log")
#define DEFAULT_LOG_FILE_MAXSTRLEN 48

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

const char* loggerGetLevelString(TLogLevel level) {
    switch (level) {
        case LOG_DEBUG:
            return "DEBUG";
        case LOG_INFO:
            return "INFO";
        case LOG_WARNING:
            return "WARNING";
        case LOG_ERROR:
            return "ERROR";
        case LOG_FATAL:
            return "FATAL";
        default:
            return "UNKNOWN";
    }
}

#ifndef DISABLE_LOGGER

/** The buffer where logs are buffered. */
static char* buffer = NULL;
static size_t bufferStart = 0, bufferLength = 0, bufferCapacity = 0;

/** The file descriptor for writing logs to disk, or -1 if we're not doing that. */
static int logFileFd = -1;
static TSelector selector = NULL;
static TLogLevel logLevel = MIN_LOG_LEVEL;

/** The stream for writing logs to, or NULL if we're not doing that. */
static FILE* logStream = NULL;

/**
 * @brief Attempts to make at least len bytes available in the log buffer.
 */
static inline void makeBufferSpace(size_t len) {
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

            // The buffer isn't large enough, let's try to expand it, or at
            // least compact it to make as much space available as possible.
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
}

/**
 * @brief Attempts to flush as much of the logging buffer into the logging file as it can.
 * This is performed with nonblocking writes. If any bytes are left for writing, we tell the
 * selector to notify us when writing is available and retry once that happens.
 */
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
        fcntl(logFileFd, F_SETFL, flags & (~O_NONBLOCK));
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

/**
 * @brief Attempts to open a file for logging. Returns the fd, or -1 if failed.
 */
static int tryOpenLogfile(const char* logFile, struct tm tm) {
    if (logFile == NULL)
        return -1;

    char logfilebuf[DEFAULT_LOG_FILE_MAXSTRLEN + 1];

    // If logFile is "", then we instead of the default log file name.
    if (logFile[0] == '\0') {
        snprintf(logfilebuf, DEFAULT_LOG_FILE_MAXSTRLEN, DEFAULT_LOG_FILE, tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900);
        logFile = logfilebuf;

        // If the default log folder isn't created, create it.
        mkdir(DEFAULT_LOG_FOLDER, LOG_FOLDER_PERMISSION_BITS);
    }

    // Warning: If a custom logFile is specified and it is within uncreated folders, this open will fail.
    int fd = open(logFile, LOG_FILE_OPEN_FLAGS, LOG_FILE_PERMISSION_BITS);
    if (fd < 0) {
        fprintf(stderr, "WARNING: Failed to open logging file at %s. The server will still run, but with logging disabled.\n", logFile);
        return -1;
    }

    return fd;
}

int loggerInit(TSelector selectorParam, const char* logFile, FILE* logStreamParam) {
    // Get the local time (to log when the server started)
    time_t timeNow = time(NULL);
    struct tm tm = *localtime(&timeNow);

    selector = selectorParam;
    logFileFd = selectorParam == NULL ? -1 : tryOpenLogfile(logFile, tm);
    logStream = logStreamParam;
    logLevel = MIN_LOG_LEVEL;

    // If we opened a file for writing logs, register it in the selector.
    if (logFileFd >= 0)
        selector_register(selector, logFileFd, &fdHandler, OP_NOOP, NULL);

    // If we have any form of logging enabled, allocate a buffer for logging.
    if (logFileFd >= 0 || logStream != NULL) {
        buffer = malloc(LOG_MIN_BUFFER_SIZE);
        bufferCapacity = LOG_MIN_BUFFER_SIZE;
        bufferLength = 0;
        bufferStart = 0;
        if (buffer == NULL) {
            close(logFileFd);
            logFileFd = -1;
            fprintf(stderr, "WARNING: Failed to malloc a buffer for logging. You don't have 4KBs?\n");
            return -1;
        }
    }

    return 0;
}

int loggerFinalize() {
    // If a logging file is opened, flush buffers, unregister it, and close it.
    if (logFileFd >= 0) {
        selector_unregister_fd(selector, logFileFd); // This will also call the TFdHandler's close, and close the file.
        selector = NULL;
    }

    // If we allocated a buffer, free it.
    if (buffer != NULL) {
        free(buffer);
        buffer = NULL;
        bufferCapacity = 0;
        bufferLength = 0;
        bufferStart = 0;
    }

    // The logger does not handle closing the stream. We set it to NULL and forget.
    logStream = NULL;
    return 0;
}

void loggerSetLevel(TLogLevel level) {
    logLevel = level;
}

int loggerIsEnabledFor(TLogLevel level) {
    return level >= logLevel && (logFileFd > 0 || logStream != NULL);
}

void loggerPrePrint() {
    makeBufferSpace(LOG_BUFFER_MAX_PRINT_LENGTH);
}

void loggerGetBufstartAndMaxlength(char** bufstartVar, size_t* maxlenVar) {
    *maxlenVar = bufferCapacity - bufferLength - bufferStart;
    *bufstartVar = buffer + bufferStart + bufferLength;
}

/**
 * @brief Called by the logf macro to perform error checking and log flushing.
 */
int loggerPostPrint(int written, size_t maxlen) {
    if (written < 0) {
        fprintf(stderr, "Error: snprintf(): %s\n", strerror(errno));
        return -1;
    }

    if ((size_t)written >= maxlen) {
        fprintf(stderr, "Error: %lu bytes of logs possibly lost. Slow disk?\n", written - maxlen + 1);
        written = maxlen - 1;
    }

    if (logStream != NULL) {
        fprintf(logStream, "%s", buffer + bufferStart + bufferLength);
    }

    // If there's no output file, then we printed the results to the stream but don't
    // update bufferLength because we're not saving anything in the buffer.
    if (logFileFd >= 0) {
        bufferLength += written;
        tryFlushBufferToFile();
    }
    return 0;
}

void logClientAuthenticated(int clientId, const char* username, int successful) {
    if (username == NULL) {
        logf(LOG_INFO, "Client %d %ssuccessfully authenticated with no authentication method%s", clientId, successful ? "" : "un", successful ? "" : "... what?");
    } else {
        logf(LOG_INFO, "Client %d %ssuccessfully authenticated as \"%s\"", clientId, successful ? "" : "un", username);
    }
}

#endif // #ifndef DISABLE_LOGGER