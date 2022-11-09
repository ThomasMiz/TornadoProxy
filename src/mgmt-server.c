#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "selector.h"

#define MGMTADDR_4 "127.0.0.1"

static bool finish = false;

int main(int argc, char *argv[]) {

    struct sockaddr_in addr;
    int sock;

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("Socket for IPv4 failed");
        close(sock);
        return -1;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(9090);

    if(inet_pton(AF_INET, MGMTADDR_4, &addr.sin_addr) != 1) {
        perror("inet_pton() failed for IPv4");
        close(sock);
        return -1;
    }
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0){
        perror("Error binding socket");
        close(sock);
        return -1;
	}

    if(listen(sock, 1) < 0) {
        perror("Error listening on socket");
        close(sock);
        return -1;
    }

    const TSelectorInit conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0,
        },
    };

    if (selector_init(&conf) != 0){
		perror("Selector init failed");
        close(sock);
        return -1;
	}

    TSelector selector = selector_new(1024);
    if (selector == NULL){
		perror("selector_new() failed");
		exit(3);
	}

    const TFdHandler mgmtHandler = {
        .handle_read = NULL,
        .handle_write = NULL,
        .handle_close = NULL,
    };

    if (selector_fd_set_nio(sock) == -1){
        perror("Error getting socket flags");
        close(sock);
        return -1;
    }

    if(selector_register(selector, sock, &mgmtHandler, OP_READ, NULL) != 0){
        perror("Error registering flag");
        close(sock);
        return -1;
    }

    while (!finish) {
		TSelectorStatus ss = selector_select(selector);
		if (ss != 0){
			perror("selector_select() failed. Aborting execution");
			exit(1);
		}
	}

    if(selector != NULL)
		selector_destroy(selector);
		
	selector_close();

    return 0;
}