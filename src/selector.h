#ifndef SELECTOR_H_
#define SELECTOR_H_

#include <stdbool.h>
#include <sys/time.h>
#include <unistd.h>

/**
 * selector.c - un muliplexor de entrada salida
 *
 * Un selector permite manejar en un único hilo de ejecución la entrada salida
 * de file descriptors de forma no bloqueante.
 *
 * Esconde la implementación final (select(2) / poll(2) / epoll(2) / ..)
 *
 * El usuario registra para un file descriptor especificando:
 *  1. un handler: provee funciones callback que manejarán los eventos de
 *     entrada/salida
 *  2. un interés: que especifica si interesa leer o escribir.
 *
 * Es importante que los handlers no ejecute tareas bloqueantes ya que demorará
 * el procesamiento del resto de los descriptores.
 *
 * Si el handler requiere bloquearse por alguna razón (por ejemplo realizar
 * una resolución de DNS utilizando getaddrinfo(3)), tiene la posiblidad de
 * descargar el trabajo en un hilo notificará al selector que el resultado del
 * trabajo está disponible y se le presentará a los handlers durante
 * la iteración normal. Los handlers no se tienen que preocupar por la
 * concurrencia.
 *
 * Dicha señalización se realiza mediante señales, y es por eso que al
 * iniciar la librería `TSelectorInit' se debe configurar una señal a utilizar.
 *
 * Todos métodos retornan su estado (éxito / error) de forma uniforme.
 * Puede utilizar `selector_error' para obtener una representación human
 * del estado. Si el valor es `SELECTOR_IO' puede obtener información adicional
 * en errno(3).
 *
 * El flujo de utilización de la librería es:
 *  - iniciar la libreria `TSelectorInit'
 *  - crear un selector: `selector_new'
 *  - registrar un file descriptor: `selector_register_fd'
 *  - esperar algún evento: `selector_iteratate'
 *  - destruir los recursos de la librería `selector_close'
 */
typedef struct fdselector* TSelector;

/** valores de retorno. */
typedef enum {
    /** llamada exitosa */
    SELECTOR_SUCCESS = 0,
    /** no pudimos alocar memoria */
    SELECTOR_ENOMEM = 1,
    /** llegamos al límite de descriptores que la plataforma puede manejar */
    SELECTOR_MAXFD = 2,
    /** argumento ilegal */
    SELECTOR_IARGS = 3,
    /** descriptor ya está en uso */
    SELECTOR_FDINUSE = 4,
    /** I/O error check errno */
    SELECTOR_IO = 5,
} TSelectorStatus;

/** retorna una descripción humana del fallo */
const char* selector_error(const TSelectorStatus status);

/** opciones de inicialización del selector */
typedef struct {
    /** señal a utilizar para notificaciones internas */
    const int signal;

    /** tiempo máximo de bloqueo durante `selector_iteratate' */
    struct timespec select_timeout;
} TSelectorInit;

/** inicializa la librería */
TSelectorStatus selector_init(const TSelectorInit* c);

/** deshace la incialización de la librería */
TSelectorStatus selector_close(void);

/* instancia un nuevo selector. returna NULL si no puede instanciar  */
TSelector selector_new(const size_t initial_elements);

/** destruye un selector creado por _new. Tolera NULLs */
void selector_destroy(TSelector s);

/**
 * Intereses sobre un file descriptor (quiero leer, quiero escribir, …)
 *
 * Son potencias de 2, por lo que se puede requerir una conjunción usando el OR
 * de bits.
 *
 * OP_NOOP es útil para cuando no se tiene ningún interés.
 */
typedef enum {
    OP_NOOP = 0,
    OP_READ = 1 << 0,
    OP_WRITE = 1 << 2,
} TFdInterests;

/**
 * Quita un interés de una lista de intereses
 */
#define INTEREST_OFF(FLAG, MASK) ((FLAG) & ~(MASK))

/**
 * Argumento de todas las funciones callback del handler
 */
typedef struct {
    /** el selector que dispara el evento */
    TSelector s;
    /** el file descriptor en cuestión */
    int fd;
    /** dato provisto por el usuario */
    void* data;
} TSelectorKey;

/**
 * Manejador de los diferentes eventos..
 */
typedef struct {
    void (*handle_read)(TSelectorKey* key);
    void (*handle_write)(TSelectorKey* key);
    void (*handle_block)(TSelectorKey* key);

    /**
     * llamado cuando se se desregistra el fd
     * Seguramente deba liberar los recusos alocados en data.
     */
    void (*handle_close)(TSelectorKey* key);

} TFdHandler;

/**
 * registra en el selector `s' un nuevo file descriptor `fd'.
 *
 * Se especifica un `interest' inicial, y se pasa handler que manejará
 * los diferentes eventos. `data' es un adjunto que se pasa a todos
 * los manejadores de eventos.
 *
 * No se puede registrar dos veces un mismo fd.
 *
 * @return 0 si fue exitoso el registro.
 */
TSelectorStatus selector_register(TSelector s, const int fd, const TFdHandler* handler, const TFdInterests interest, void* data);

/**
 * desregistra un file descriptor del selector
 */
TSelectorStatus selector_unregister_fd(TSelector s, const int fd);

/**
 * desregistra un file descriptor del selector sin llamar a su close
 */
TSelectorStatus selector_unregister_fd_noclose(TSelector s, const int fd);

/** permite cambiar los intereses para un file descriptor */
TSelectorStatus selector_set_interest(TSelector s, int fd, TFdInterests i);

/** permite cambiar los intereses para un file descriptor */
TSelectorStatus selector_set_interest_key(TSelectorKey* key, TFdInterests i);

/** Devuelve los intereses del selector key */
TSelectorStatus selector_get_interests_key(TSelectorKey* key, TFdInterests* i);

/** Devuelve los intereses del selector */
TSelectorStatus selector_get_interests(TSelector s, int fd, TFdInterests* i);

/**
 * se bloquea hasta que hay eventos disponible y los despacha.
 * Retorna luego de cada iteración, o al llegar al timeout.
 */
TSelectorStatus selector_select(TSelector s);

/**
 * Método de utilidad que activa O_NONBLOCK en un fd.
 *
 * retorna -1 ante error, y deja detalles en errno.
 */
int selector_fd_set_nio(const int fd);

/** notifica que un trabajo bloqueante terminó */
TSelectorStatus selector_notify_block(TSelector s, const int fd);

#endif
