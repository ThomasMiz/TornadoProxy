#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#include "auth/authParser.h"
#include "buffer.h"
#include "negotiation/negotiation.h"
#include "request/requestParser.h"
#include "selector.h"
#include "socks5.h"
#include "copy.h"
#include "stm.h"
#include "passwordDissector.h"
#include <stdbool.h>
#include <netdb.h>

// obtiene el struct socks5* desde la key
#define ATTACHMENT(key) ((TClientData*)(key)->data)
#define BUFFER_SIZE 8192
#define N(x) (sizeof(x) / sizeof((x)[0]))

typedef struct TClientData {
    TFdHandler handler;

    struct state_machine stm;
    union {
        TNegParser negParser;
        TReqParser reqParser;
        TAuthParser authParser;
    } client;

    bool closed;

    TPDissector pDissector;

    // Added this buffer, consider removing the plain buffer from this struct.
    struct buffer clientBuffer;
    uint8_t inClientBuffer[BUFFER_SIZE];

    struct buffer originBuffer;
    uint8_t inOriginBuffer[BUFFER_SIZE];

    struct addrinfo* origin_resolution;
    int client_fd;
    // informacion del OS
    int origin_fd;

    connections_t connections;
} TClientData;

enum socks_state {
    /*
        recibe el mensaje `hello` del cliente y lo procesa
    Intereses:
        - OP_READ sobre client_fd
    Transiciones:
        - HELLO_READ mientras el mensaje no esta completo
        - HELLO_WRITE cuando esta completo
        - ERROR ante cualquier error (IO/parseo)
    */
    NEGOTIATION_READ = 0,

    /*
        envia la respuesta del `hello` al cliente
    Intereses:
        - OP_WRITE sobre client_fd
    Transiciones:
        - HELLO_WRITE mientras queden bytes por enviar
        - REQUEST_READ cuando se enviaron todos los bytes
        - ERROR ante cualquier error (IO/parseo)
    */
    NEGOTIATION_WRITE,

    AUTH_READ,
    AUTH_WRITE,

    /*
        recibe el mensaje `request` del cliente e inicia su proceso
    Intereses:
        - OP_READ sobre client_fd
    Transiciones:
        - REQUEST_READ mientras el mensaje no este completo
        - REQUEST_RESOLV si quiere resolver un nombre DNS
        - REQUEST_CONNECTING si no requiere resolver DNS y podemos inicial la conexion con el OS
        - REQUEST_WRITE si determinamos que el mensaje no lo podemos procesar (ej. no se soporta un comando)
        - ERROR ante cualquier error (IO/parseo)
    */
    REQUEST_READ,

    /*
        Espera la resolucion DNS
    Intereses:
        - OP_NOOP sobre client_fd. Espera un evento de que la tarea bloqueante terminó
    Transiciones:
        - REQUEST_CONNECTING si se logra la resolucion y se puede iniciar la conexion al OS.
        - REQUEST_WRITE en otro caso
    */
    REQUEST_RESOLV,

    /*
        Espera que se establezca la conesion al OS
    Intereses:
        - OP_WRITE sobre client_fd
    Transiciones:
        - REQUEST_CWRITE cuando se haya logrado o no establecer la conexion
    */
    REQUEST_CONNECTING,

    /*
        Envia la respuesta del `request` al cliente
    Intereses:
        - OP_WRITE sobre client_fd
        - OP_NOOP sobre origin_fd
    Transiciones:
        - HELLO_WRITE mientras queden bytes por enviar
        - COPY si el request fue exitoso y teemos que copiar el contenido de los descriptores
        - ERRO ante I/O error
    */
    REQUEST_WRITE,

    /*
        Copia bytes entre client_fd y origin_fd
    Intereses:
        - OP_READ si hay espacio para escribir en el buffer de lectura
        - OP_WRITE si hay bytes para leer en el buffer de escritura
    Transiciones:
        - DONE cuando no queda nada mas por copiar
    */
    COPY,

    // estados terminales
    DONE,
    ERROR,

};

void socksv5_passive_accept(TSelectorKey* key);
unsigned socksv5_handle_read(TSelectorKey* key);
unsigned socksv5_handle_write(TSelectorKey* key);
void socksv5_handle_close(const unsigned int, TSelectorKey* key);
TFdHandler* get_state_handler();

#endif
