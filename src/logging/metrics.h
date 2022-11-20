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
 * @brief Initializes the metrics system.
 */
void metricsInit();

/**
 * @brief Registers into the metrics that a new client connection has been received.
 */
void metricsRegisterNewClient();

/**
 * @brief Registers into the metrics that an existing client connection has terminated.
 */
void metricsRegisterClientDisconnected();

/**
 * @brief Register into the metrics that a client sent or received a specified amount of bytes to
 * the remote server it's connected to.
 * @param bytesSent The amount of bytes sent by the client to the remote server.
 * @param bytesReceived The amount of bytes sent by the remote server to the client.
 */
void metricsRegisterBytesTransfered(size_t bytesSent, size_t bytesReceived);

/**
 * @brief Gets a snapshot of the server's current metrics.
 * @param snapshot A pointer to the struct to where the metrics snapshot will be written.
 */
void getMetricsSnapshot(TMetricsSnapshot* snapshot);

#endif