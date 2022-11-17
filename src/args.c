#include <errno.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <string.h> /* memset */

#include "args.h"

static unsigned short
port(const char* s) {
    char* end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
        exit(1);
        return 1;
    }
    return (unsigned short)sl;
}

static void
user(char* s, struct users* user) {
    char* p = strchr(s, ':');
    if (p == NULL) {
        fprintf(stderr, "password not found\n");
        exit(1);
    } else {
        *p = 0;
        p++;
        user->name = s;
        user->pass = p;
    }
}

static void
version(void) {
    fprintf(stderr, "socks5v version 0.0\n"
                    "ITBA Protocolos de Comunicación 2022/2 -- Grupo 10\n");
}

static void
usage(const char* progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
            "   -L <conf  addr>  Dirección donde servirá el servicio de management.\n"
            "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
            "   -P <conf port>   Puerto entrante conexiones configuracion\n"
            "   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
            "   -v               Imprime información sobre la versión versión y termina.\n"
            "\n",
            progname);
    exit(1);
}

void parse_args(const int argc, char** argv, struct socks5args* args) {
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->socksAddr = "0.0.0.0";
    args->socksPort = 1080;

    args->mngAddr = "127.0.0.1";
    args->mngPort = 8080;

    args->disectorsEnabled = true;
    args->nusers = 0;

    int c;
    while (true) {

        c = getopt(argc, argv, "hl:L:Np:P:U:u:v");;
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'l':
                args->socksAddr = optarg;
                break;
            case 'L':
                args->mngAddr = optarg;
                break;
            case 'N':
                args->disectorsEnabled = false;
                break;
            case 'p':
                args->socksPort = port(optarg);
                break;
            case 'P':
                args->mngPort = port(optarg);
                break;
            case 'u':
                if (args->nusers >= MAX_USERS) {
                    fprintf(stderr, "maximun number of command line users reached: %d.\n", MAX_USERS);
                    exit(1);
                } else {
                    user(optarg, args->users + args->nusers);
                    args->nusers++;
                }
                break;
            case 'v':
                version();
                exit(0);
                break;
            default:
                fprintf(stderr, "unknown argument %d.\n", c);
                exit(1);
        }
    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}
