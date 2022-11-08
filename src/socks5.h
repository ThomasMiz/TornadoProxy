#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#include "selector.h"
#include "stm.h"
#include "buffer.h"
#include <netdb.h>

#define BUFFER_SIZE 8192
#define N(x) (sizeof(x) / sizeof((x)[0]))

typedef struct {
    TFdHandler handler;
    uint8_t client_buffer_array[BUFFER_SIZE];
    uint8_t origin_buffer_array[BUFFER_SIZE];
    buffer client_buffer;
    buffer origin_buffer;
    unsigned int bufferLength;
    struct state_machine stm;

    struct addrinfo* origin_resolution;

    int client_fd;

    // informacion del OS
    int origin_fd;
} TClientData;



#define ATTACHMENT(key) ((TClientData*)(key)->data)

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
    //    HELLO_READ,

    /*
        envia la respuesta del `hello` al cliente

    Intereses:
        - OP_WRITE sobre client_fd

    Transiciones:
        - HELLO_WRITE mientras queden bytes por enviar
        - REQUEST_READ cuando se enviaron todos los bytes
        - ERROR ante cualquier error (IO/parseo)
    */
    //    HELLO_WRITE,

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
    //    REQUEST_READ,

    /*
        Espera la resolucion DNS

    Intereses:
        - OP_NOOP sobre client_fd. Espera un evento de que la tarea bloqueante terminó

    Transiciones:
        - REQUEST_CONNECTING si se logra la resolucion y se puede iniciar la conexion al OS.
        - REQUEST_WRITE en otro caso
    */
    //    REQUEST_RESOLV,

    /*
        Espera que se establezca la conesion al OS

    Intereses:
        - OP_WRITE sobre client_fd

    Transiciones:
        - REQUEST_WRITE cuando se haya logrado o no establecer la conexion
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
    //    REQUEST_WRITE,

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
TFdHandler * get_state_handler();


#endif