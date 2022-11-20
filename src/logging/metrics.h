#ifndef _METRICS_H_
#define _METRICS_H_

#include <stdlib.h>

/**
 * Represents a snapshot of the proxy server's metrics.
 */
typedef struct {
    /**
     * The amount of client connections opened at the time this snapshot was taken.
     */
    size_t currentConnectionCount;

    /**
     * The total amount of client connections this proxy handled throughout it's lifetime.
     */
    size_t totalConnectionCount;

    /**
     * The maximum amount of concurrent client connections this proxy has had to handle
     * throughout it's lifetime.
     */
    size_t maxConcurrentConnections;

    /**
     * The total amount of bytes sent by clients to remote servers through this proxy.
     */
    size_t totalBytesSent;

    /**
     * The total amount of bytes received by clients from remote servers through this proxy.
     */
    size_t totalBytesReceived;
} TMetricsSnapshot;

/**
 * @brief Gets a snapshot of the server's current metrics.
 * @param snapshot A pointer to the struct to where the metrics snapshot will be written.
 */
void getMetricsSnapshot(TMetricsSnapshot* snapshot);

#endif