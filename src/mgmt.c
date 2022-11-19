#include "mgmt.h"
#include "logger.h"
#include "mgmtAuth.h"

static void mgmtdoneArrival(const unsigned state, TSelectorKey* key) {
    printf("Done state \n");
}
static void mgmterrorArrival(const unsigned state, TSelectorKey* key) {
    printf("Error state \n");
}

static void mgmtClose_connection(TSelectorKey * key);
static const struct state_definition client_statb1[] = {
    {
        .state = MGMT_AUTH_READ,
        .on_arrival = mgmtAuthReadInit,
        .on_read_ready = mgmtAuthRead,

    },
    {
        .state = MGMT_AUTH_WRITE,
        .on_write_ready = mgmtAuthWrite,
    },
    {
        .state = MGMT_REQUEST_READ,
        // .on_arrival = requestReadInit,
        // .on_read_ready = requestRead,
    },
    {
        .state = MGMT_REQUEST_WRITE,
        // .on_write_ready = requestWrite,
    },
    {
        .state = MGMT_DONE,
        .on_arrival = mgmtdoneArrival,
    },
    {
        .state = MGMT_ERROR,
        .on_arrival = mgmterrorArrival,
    }};

static void mgmt_read(TSelectorKey* key);
static void mgmt_write(TSelectorKey* key);
static void mgmt_close(TSelectorKey* key);
static void mgmt_block(TSelectorKey* key);
static TFdHandler handler = {
    .handle_read = mgmt_read,
    .handle_write = mgmt_write,
    .handle_close = mgmt_close,
    .handle_block = mgmt_block,
};



void mgmt_close(TSelectorKey* key) {
    struct state_machine* stm = &GET_ATTACHMENT(key)->stm;
    stm_handler_close(stm, key);
    mgmtClose_connection(key);
}

static void mgmt_read(TSelectorKey* key) {
    struct state_machine* stm = &GET_ATTACHMENT(key)->stm;
    const enum mgmt_state st = stm_handler_read(stm, key);
    if(st == MGMT_ERROR || st == MGMT_DONE){
        mgmtClose_connection(key);
    }
}

static void mgmt_write(TSelectorKey* key) {
    struct state_machine* stm = &GET_ATTACHMENT(key)->stm;
    const enum mgmt_state st = stm_handler_write(stm, key);
    if(st == MGMT_ERROR || st == MGMT_DONE){
        mgmtClose_connection(key);
    }
}

static void mgmt_block(TSelectorKey* key) {
    struct state_machine* stm = &GET_ATTACHMENT(key)->stm;
    const enum mgmt_state st = stm_handler_block(stm, key);
    if(st == MGMT_ERROR || st == MGMT_DONE){
        mgmtClose_connection(key);
    }
}

// static const char *helloMessage = "mgmt server up!";


// static void handleMgmtRead(TSelectorKey *key);
// static void handleMgmtWrite(TSelectorKey *key);
// static void handleMgmtClose(TSelectorKey *key);
static TMgmtClient *initMgmtClient(int sock);
// static void parseMgmtClientRequest(TMgmtClient* clientData);

// static TFdHandler clientActionHandlers = {
//     .handle_read   = handleMgmtRead,
//     .handle_write  = handleMgmtWrite,
//     .handle_close  = handleMgmtClose,
//     .handle_block  = NULL,
// };

static TMgmtClient *initMgmtClient(int socket) {

    TMgmtClient* clientData = calloc(1, sizeof(TMgmtClient));
    if (clientData == NULL) {
        perror("Failed to alloc clientData for new client (mgmt)!\n");
        free(clientData);
        close(socket);
        return NULL;
    }
    buffer_init(&(clientData->buffer),MGMT_BUFFER_SIZE, clientData->rawBuffer);
    return clientData;
}

void mgmtPassiveAccept(TSelectorKey* key) {
    struct sockaddr_storage clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);
    int newClientSocket = accept(key->fd, (struct sockaddr*)&clientAddress, &clientAddressLen);
    log(DEBUG,"New mgmt client accepted at socket fd %d", newClientSocket);

    // Consider using a function to initialize the TClientData structure.
    TMgmtClient * clientData = initMgmtClient(key->fd);
  

    TFdHandler* handler = &clientData->handler;
    handler->handle_read = mgmt_read;
    handler->handle_write = mgmt_write;
    handler->handle_close = mgmt_close;
    handler->handle_block = mgmt_block;

    clientData->stm.initial = MGMT_AUTH_READ;
    clientData->stm.max_state = MGMT_ERROR;
    clientData->closed = false;
    clientData->stm.states = client_statb1;
    clientData->clientFd = newClientSocket;
    // clientData->originFd=-1;

    buffer_init(&clientData->buffer, MGMT_BUFFER_SIZE, clientData->rawBuffer);
    // buffer_init(&clientData->clientBuffer, BUFFER_SIZE, clientData->inClientBuffer);

    stm_init(&clientData->stm);

    TSelectorStatus status = selector_register(key->s, newClientSocket, handler, OP_READ, clientData);

    if (status != SELECTOR_SUCCESS) {
        log(LOG_ERROR, "Failed to register new mgmt client into selector: %s", selector_error(status));
        free(clientData);
        return;
    }
    log(INFO, "New mgmt client registered successfully t socket fd %d", newClientSocket);
}

// static void handleMgmtRead(TSelectorKey *key) {
//     TMgmtClient* clientData = key->data;
//     size_t size;

//     uint8_t* writePtr = buffer_write_ptr(&(clientData->buffer), &size);
//     ssize_t received = recv(key->fd, writePtr, size, 0);

//     if (received <= 0) { 
//         printf("recv() returned %ld, closing mgmt client %d\n", received, key->fd);
//         selector_unregister_fd(key->s, key->fd);
//         return;
//     }

//     buffer_write_adv(&(clientData->buffer), received);

//     printf("recv() %ld bytes from mgmt client %d\n", received, key->fd);

//     parseMgmtClientRequest(clientData);

//     TFdInterests newInterests = OP_WRITE;
//     if (buffer_can_read(&(clientData->buffer)))
//         newInterests |= OP_READ;
    
//     selector_set_interest_key(key, newInterests);
// }

// static void handleMgmtWrite(TSelectorKey *key) {
//     TMgmtClient* clientData = key->data;
//     size_t size;
//     uint8_t* readPtr = buffer_read_ptr(&(clientData->buffer), &size);

//     ssize_t sent = send(key->fd, readPtr, size, 0);
//     if (sent <= 0) { 
//         printf("send() returned %ld, closing mgmt client %d (mgmt)\n", sent, key->fd);
//         selector_unregister_fd(key->s, key->fd);
//         return;
//     }

//     buffer_read_adv(&(clientData->buffer), sent);

//     printf("send() %ld bytes to client %d (mgmt)\n", sent, key->fd);
    
//     TFdInterests newInterests = OP_READ;
//     if (buffer_can_write(&(clientData->buffer)))
//         newInterests |= OP_WRITE;
    
//     selector_set_interest_key(key, newInterests);
// }

// static void handleMgmtClose(TSelectorKey *key) {
//     printf("Client closed: %d (mgmt)\n", key->fd);
//     TMgmtClient* clientData = key->data;
//     free(clientData->rawBuffer);
//     free(clientData);
//     close(key->fd);
// }

// static void parseMgmtClientRequest(TMgmtClient* clientData){
//     size_t size;
//     char buf[MGMT_BUFFER_SIZE];

//     uint8_t* readPtr = buffer_read_ptr(&(clientData->buffer), &size);
//     memcpy(buf, readPtr, size);
//     printf("%s\n", buf);

//     if(strcmp(buf, "USERS") == 0){
//         snprintf(buf, sizeof(buf), "%s\n", "Users list: pepito, juan, norberto");
//     } else if(strcmp(buf, "CAPA") == 0){
//         snprintf(buf, sizeof(buf), "%s\n", "Server capabilities: cry & eat");
//     } else {
//         snprintf(buf, sizeof(buf), "%s\n", "Empty");
//     }

//     buffer_read_adv(&(clientData->buffer), size);

//     uint8_t *writePtr = buffer_write_ptr(&(clientData->buffer), &size);
//     size_t bytes = strlen(buf);
//     memcpy(writePtr, buf, bytes);
//     buffer_write_adv(&(clientData->buffer), bytes);
// }

// void mgmt_passive_accept_handler(TSelectorKey *key){

//     struct sockaddr_storage clientAddress;
//     socklen_t clientAddressLen = sizeof(clientAddress);
//     int newClientSocket = accept(key->fd, (struct sockaddr*)&clientAddress, &clientAddressLen);
//     printf("New client accepted at socket fd %d (mgmt)\n", newClientSocket);
    
//     if(newClientSocket < 0){
//         perror("accept() failed. New connection refused (mgmt)\n");
//         exit(3);
//     }

//     selector_fd_set_nio(newClientSocket);
//     TMgmtClient *newClient = initMgmtClient(newClientSocket);

//     if(newClient == NULL) {
//         perror("create_mgmt_client failed.\n");
//         exit(3);
//     }
    
//     char responseBuf[MGMT_BUFFER_SIZE];
//     snprintf(responseBuf, sizeof(responseBuf), "%s\n", helloMessage);

//     size_t size;
//     uint8_t *writePtr = buffer_write_ptr(&(newClient->buffer), &size);
//     size_t bytes = strlen(responseBuf);
//     memcpy(writePtr, responseBuf, bytes);
//     buffer_write_adv(&(newClient->buffer), bytes);

//     selector_register(key->s, newClientSocket, &clientActionHandlers, OP_WRITE, newClient);
// }

static void mgmtClose_connection(TSelectorKey * key) {
    TMgmtClient * data = GET_ATTACHMENT(key);
    if (data->closed)
        return;
    data->closed = true;

    int clientSocket = data->clientFd;
    // int serverSocket = data->originFd;
    if (clientSocket != -1) {
        selector_unregister_fd(key->s, clientSocket);
        close(clientSocket);
    }

    // if (data->originResolution != NULL) {
    //     if(data->client.reqParser.atyp != REQ_ATYP_DOMAINNAME){
    //         free(data->originResolution->ai_addr);
    //         free(data->originResolution);
    //     }else {
    //         freeaddrinfo(data->originResolution);
    //     }
    // }

    free(data);
}

