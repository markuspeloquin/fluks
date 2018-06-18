/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "endian.h"

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
