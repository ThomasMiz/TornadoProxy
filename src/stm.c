// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

/**
 * stm.c - pequeño motor de maquina de estados donde los eventos son los
 *         del selector.c
 */
#include "stm.h"
#include "logging/logger.h"
#include <stdio.h>
#include <stdlib.h>

#define N(x) (sizeof(x) / sizeof((x)[0]))

void stm_init(struct state_machine* stm) {
    // verificamos que los estados son correlativos, y que están bien asignados.
    for (unsigned i = 0; i <= stm->max_state; i++) {
        if (i != stm->states[i].state) {
            abort();
        }
    }

    if (stm->initial < stm->max_state) {
        stm->current = NULL;
    } else {
        abort();
    }
}

inline static void
handle_first(struct state_machine* stm, TSelectorKey* key) {
    if (stm->current == NULL) {
        stm->current = stm->states + stm->initial;
        if (NULL != stm->current->on_arrival) {
            stm->current->on_arrival(stm->current->state, key);
        }
    }
}

inline static void jump(struct state_machine* stm, unsigned next, TSelectorKey* key) {
    if (next > stm->max_state) {
        logf(LOG_DEBUG, "State state machine jump: %d", key->fd);
        abort();
    }
    if (stm->current != stm->states + next) {
        if (stm->current != NULL && stm->current->on_departure != NULL) {
            stm->current->on_departure(stm->current->state, key);
        }
        stm->current = stm->states + next;

        if (NULL != stm->current->on_arrival) {
            stm->current->on_arrival(stm->current->state, key);
        }
    }
}

unsigned
stm_handler_read(struct state_machine* stm, TSelectorKey* key) {
    handle_first(stm, key);
    if (stm->current->on_read_ready == 0) {
        logf(LOG_DEBUG, "State machine read handler: %d STATE: %ud", key->fd, stm->current->state);
        abort();
    }
    const unsigned int ret = stm->current->on_read_ready(key);
    jump(stm, ret, key);

    return ret;
}

unsigned
stm_handler_write(struct state_machine* stm, TSelectorKey* key) {
    handle_first(stm, key);
    if (stm->current->on_write_ready == 0) {
        logf(LOG_DEBUG, "State machine write handler: %d", key->fd);
        abort();
    }
    const unsigned int ret = stm->current->on_write_ready(key);
    jump(stm, ret, key);

    return ret;
}

unsigned
stm_handler_block(struct state_machine* stm, TSelectorKey* key) {
    handle_first(stm, key);
    if (stm->current->on_block_ready == 0) {
        logf(LOG_DEBUG, "State machine block handler: %d", key->fd);
        abort();
    }
    const unsigned int ret = stm->current->on_block_ready(key);
    jump(stm, ret, key);

    return ret;
}

void stm_handler_close(struct state_machine* stm, TSelectorKey* key) {
    if (stm->current != NULL && stm->current->on_departure != NULL) {
        stm->current->on_departure(stm->current->state, key);
    }
}

unsigned
stm_state(struct state_machine* stm) {
    unsigned ret = stm->initial;
    if (stm->current != NULL) {
        ret = stm->current->state;
    }
    return ret;
}
