#include "mgmt.h"

static const char *helloMessage = "mgmt server up!";

typedef struct {
    struct buffer buffer;
    uint8_t *rawBuffer;
} TMgmtClient;

static void handleMgmtRead(TSelectorKey *key);
static void handleMgmtWrite(TSelectorKey *key);
static void handleMgmtClose(TSelectorKey *key);
static TMgmtClient *initMgmtClient(int sock);
static void parseMgmtClientRequest(TMgmtClient* clientData);

static TFdHandler clientActionHandlers = {
    .handle_read   = handleMgmtRead,
    .handle_write  = handleMgmtWrite,
    .handle_close  = handleMgmtClose,
    .handle_block  = NULL,
};

static TMgmtClient *initMgmtClient(int socket) {

    TMgmtClient* clientData = calloc(1, sizeof(TMgmtClient));
    if (clientData == NULL || (clientData->rawBuffer = malloc(CLIENT_MGMT_BUFFER_SIZE)) == NULL) {
        perror("Failed to alloc clientData for new client (mgmt)!\n");
        free(clientData);
        close(socket);
        return NULL;
    }
    buffer_init(&(clientData->buffer), CLIENT_MGMT_BUFFER_SIZE, clientData->rawBuffer);
    return clientData;
}

static void handleMgmtRead(TSelectorKey *key) {
    TMgmtClient* clientData = key->data;
    size_t size;

    uint8_t* writePtr = buffer_write_ptr(&(clientData->buffer), &size);
    ssize_t received = recv(key->fd, writePtr, size, 0);

    if (received <= 0) { 
        printf("recv() returned %ld, closing client %d\n", received, key->fd);
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    buffer_write_adv(&(clientData->buffer), received);

    printf("recv() %ld bytes from client %d\n", received, key->fd);

    parseMgmtClientRequest(clientData);

    TFdInterests newInterests = OP_WRITE;
    if (buffer_can_read(&(clientData->buffer)))
        newInterests |= OP_READ;
    
    selector_set_interest_key(key, newInterests);
}

static void handleMgmtWrite(TSelectorKey *key) {
    TMgmtClient* clientData = key->data;
    size_t size;
    uint8_t* readPtr = buffer_read_ptr(&(clientData->buffer), &size);

    ssize_t sent = send(key->fd, readPtr, size, 0);
    if (sent <= 0) { 
        printf("send() returned %ld, closing client %d (mgmt)\n", sent, key->fd);
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    buffer_read_adv(&(clientData->buffer), sent);

    printf("send() %ld bytes to client %d (mgmt)\n", sent, key->fd);
    
    TFdInterests newInterests = OP_READ;
    if (buffer_can_write(&(clientData->buffer)))
        newInterests |= OP_WRITE;
    
    selector_set_interest_key(key, newInterests);
}

static void handleMgmtClose(TSelectorKey *key) {
    printf("Client closed: %d (mgmt)\n", key->fd);
    TMgmtClient* clientData = key->data;
    free(clientData->rawBuffer);
    free(clientData);
    close(key->fd);
}

static void parseMgmtClientRequest(TMgmtClient* clientData){
    size_t size;
    static char buf[CLIENT_MGMT_BUFFER_SIZE];

    uint8_t* readPtr = buffer_read_ptr(&(clientData->buffer), &size);
    memcpy(buf, readPtr, size);
    printf("%s\n", buf);

    if(strcmp(buf, "USERS") == 0){
        snprintf(buf, sizeof(buf), "%s\n", "Users list: pepito, juan, norberto");
    } else if(strcmp(buf, "CAPA") == 0){
        snprintf(buf, sizeof(buf), "%s\n", "Server capabilities: cry & eat");
    } else {
        snprintf(buf, sizeof(buf), "%s\n", "Empty");
    }

    buffer_read_adv(&(clientData->buffer), size);

    uint8_t *writePtr = buffer_write_ptr(&(clientData->buffer), &size);
    size_t bytes = strlen(buf);
    memcpy(writePtr, buf, bytes);
    buffer_write_adv(&(clientData->buffer), bytes);
}

void mgmt_passive_accept_handler(TSelectorKey *key){

    struct sockaddr_storage clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);
    int newClientSocket = accept(key->fd, (struct sockaddr*)&clientAddress, &clientAddressLen);
    printf("New client accepted at socket fd %d (mgmt)\n", newClientSocket);
    
    if(newClientSocket < 0){
        perror("accept() failed. New connection refused (mgmt)\n");
        exit(3);
    }

    selector_fd_set_nio(newClientSocket);
    TMgmtClient *newClient = initMgmtClient(newClientSocket);

    if(newClient == NULL) {
        perror("create_mgmt_client failed.\n");
        exit(3);
    }
    
    static char responseBuf[CLIENT_MGMT_BUFFER_SIZE];
    snprintf(responseBuf, sizeof(responseBuf), "%s\n", helloMessage);

    size_t size;
    uint8_t *writePtr = buffer_write_ptr(&(newClient->buffer), &size);
    size_t bytes = strlen(responseBuf);
    memcpy(writePtr, responseBuf, bytes);
    buffer_write_adv(&(newClient->buffer), bytes);

    selector_register(key->s, newClientSocket, &clientActionHandlers, OP_WRITE, newClient);
}

