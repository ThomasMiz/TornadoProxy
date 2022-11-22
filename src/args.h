#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>

#define MAX_ARGS_USERS 10

struct users {
    char* name;
    char* pass;
};

struct socks5args {
    char* socksAddr;
    unsigned short socksPort;

    char* mngAddr;
    unsigned short mngPort;

    bool disectorsEnabled;

    unsigned short nusers;
    struct users users[MAX_ARGS_USERS];
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void parse_args(const int argc, char** argv, struct socks5args* args);

#endif
