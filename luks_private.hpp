/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <arpa/inet.h>

#include <endian.h>

// ensure ENDIAN macros exist
#include "endian_check.h"

namespace fluks {

inline void
endian_switch(uint32_t &x)
{	x = htonl(x); }

inline void
endian_switch(uint16_t &x)
{	x = htons(x); }

}

inline uint16_t
fluks::host_little(uint16_t x)
{
#if BYTE_ORDER == BIG_ENDIAN
	return (x & 0x00ff) << 8 | (x & 0xff00) >> 8;
#else
	return x;
#endif
}

inline uint32_t
fluks::host_little(uint32_t x)
{
#if BYTE_ORDER == BIG_ENDIAN
	return
	    (x & 0x000000ff) << 24 |
	    (x & 0x0000ff00) << 8 |
	    (x & 0x00ff0000) >> 8 |
	    (x & 0xff000000) >> 24;
#else
	return x;
#endif
}

inline void
fluks::endian_switch(struct phdr1 *h, bool process_keys)
{
#if BYTE_ORDER == BIG_ENDIAN
	// don't bother with the rest of the function, though the preprocessor
	// and the inlining compiler would eliminate most of it anyway
	return;
#else
	endian_switch(h->version);
	endian_switch(h->off_payload);
	endian_switch(h->sz_key);
	endian_switch(h->mk_iterations);
	if (!process_keys) return;
	for (size_t i = 0; i < NUM_KEYS; i++)
		endian_switch(h->keys + i);
#endif
}

inline void
fluks::endian_switch(struct key *k)
{
#if BYTE_ORDER == BIG_ENDIAN
	return;
#else
	endian_switch(k->active);
	endian_switch(k->iterations);
	endian_switch(k->off_km);
	endian_switch(k->stripes);
#endif
}
