// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "args.h"
#include <errno.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <string.h> /* memset */

static unsigned short
port(const char* s) {
    char* end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "Port should in in the range of 1-65535: %s\n", s);
        exit(1);
        return 1;
    }
    return (unsigned short)sl;
}

static void
user(char* s, struct users* user) {
    char* p = strchr(s, ':');
    if (p == NULL) {
        fprintf(stderr, "Password not found\n");
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
    fprintf(stderr, "socks5v version 1.0\n"
                    "ITBA Protocolos de Comunicación 2022/2 -- Grupo 10\n");
}

static void
usage(const char* progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Prints this help menu and then exits.\n"
            "   -l <SOCKS addr>  Specifies the source address for the socks5 server. This may be an IPv4 or IPv6 address.\n"
            "   -N               Deshabilita el passwords dissectors.\n"
            "   -L <conf addr>   Specifies the source address for the management server. This may be an IPv4 or IPv6 address.\n"
            "   -p <SOCKS port>  Specifies the source port for the socks5 server.\n"
            "   -P <conf port>   Specifies the source port for the management server.\n"
            "   -u <user>:<pass> Specifies a username and password to register into the system. This param may be specified up to 10 times.\n"
            "   -v               Display this server's version information and exit.\n"
            "\n",
            progname);
    exit(1);
}

void parse_args(const int argc, char** argv, struct socks5args* args) {
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->socksAddr = "::";
    args->socksPort = 1080;

    args->mngAddr = "127.0.0.1";
    args->mngPort = 8080;

    args->disectorsEnabled = true;
    args->nusers = 0;

    while (true) {
        int c = getopt(argc, argv, "hl:L:Np:P:U:u:v");

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
                if (args->nusers >= MAX_ARGS_USERS) {
                    fprintf(stderr, "Maximun number of command line users reached: %d.\n", MAX_ARGS_USERS);
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
                fprintf(stderr, "Unknown argument %d.\n", c);
                exit(1);
        }
    }
    if (optind < argc) {
        fprintf(stderr, "Argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}
