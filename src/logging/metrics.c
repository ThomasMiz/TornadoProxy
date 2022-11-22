// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "metrics.h"
#include <string.h>

/**
 * The current metrics values for this server.
 */
static TMetricsSnapshot metrics;

void metricsInit() {
    // Initialize all the metric values to zero.
    memset(&metrics, 0, sizeof(metrics));
}

void metricsRegisterNewClient() {
    metrics.currentConnectionCount++;
    metrics.totalConnectionCount++;
    if (metrics.currentConnectionCount > metrics.maxConcurrentConnections)
        metrics.maxConcurrentConnections = metrics.currentConnectionCount;
}

void metricsRegisterClientDisconnected() {
    metrics.currentConnectionCount--;
}

void metricsRegisterBytesTransfered(size_t bytesSent, size_t bytesReceived) {
    metrics.totalBytesSent += bytesSent;
    metrics.totalBytesReceived += bytesReceived;
}

void getMetricsSnapshot(TMetricsSnapshot* snapshot) {
    memcpy(snapshot, &metrics, sizeof(TMetricsSnapshot));
}