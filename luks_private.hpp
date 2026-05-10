#pragma once

#include "endian.h"
#include "luks.hpp"

inline void
fluks::endian_switch(struct phdr1 *h, bool process_keys) {
#if !FLUKS_IS_BIG_ENDIAN
	h->version = fluks_htobe16(h->version);
	h->off_payload = fluks_htobe32(h->off_payload);
	h->sz_key = fluks_htobe32(h->sz_key);
	h->mk_iterations = fluks_htobe32(h->mk_iterations);
	if (!process_keys) return;
	for (uint8_t i = 0; i < NUM_KEYS; i++)
		endian_switch(h->keys + i);
#endif
}

inline void
fluks::endian_switch(struct key *k) {
#if !FLUKS_IS_BIG_ENDIAN
	k->active = fluks_htobe32(k->active);
	k->iterations = fluks_htobe32(k->iterations);
	k->off_km = fluks_htobe32(k->off_km);
	k->stripes = fluks_htobe32(k->stripes);
#endif
}
