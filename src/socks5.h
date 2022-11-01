#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#include "selector.h"

void socksv5_passive_accept(struct selector_key* key);
void socksv5_handle_read(struct selector_key* key);
void socksv5_handle_write(struct selector_key* key);
void socksv5_handle_close(struct selector_key* key);

#endif