#ifndef TWOFISH_DEBUG_H
#define TWOFISH_DEBUG_H


#ifdef DEBUG
#include <stdbool.h>

#include "twofish.h"

#define IV_ROUND -100
void	twofish_debug_dump(const void *p, const char *s, int R, uint8_t XOR,
	    bool do_rot, bool show_t, bool need_swap,
	    uint32_t t0, uint32_t t1);
void	twofish_debug_dump_key(const struct twofish_key *key);
#endif


#endif
