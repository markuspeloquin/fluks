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

#ifndef FLUKS_WHIRLPOOL_H
#define FLUKS_WHIRLPOOL_H

#include <features.h>
#include <stdint.h>

#ifdef __cplusplus
// C++
#	include <cstddef>

// because I hate macros
const size_t WHIRLPOOL256_SZ_DIGEST = 32;
const size_t WHIRLPOOL384_SZ_DIGEST = 48;
const size_t WHIRLPOOL_SZ_DIGEST = 64;
const size_t WHIRLPOOL_SZ_BLOCK = 64;

#else 
/* C */
#	include <stddef.h>
#	define WHIRLPOOL_SZ_DIGEST	64
#	define WHIRLPOOL_SZ_BLOCK	64
#endif

struct whirlpool_ctx {
	/* global number of hashed bits (256-bit counter) */
	uint8_t  bitLength[32];

	/* buffer of data to hash */
	uint8_t  buffer[WHIRLPOOL_SZ_BLOCK];

	/* current number of bits on the buffer */
	int bufferBits;

	/* current (possibly incomplete) byte slot on the buffer */
	int bufferPos;

	/* the hashing state */
	uint64_t hash[WHIRLPOOL_SZ_DIGEST / sizeof(uint64_t)];
};

__BEGIN_DECLS

void	whirlpool_init(struct whirlpool_ctx *const ctx);
void	whirlpool_update(struct whirlpool_ctx *const ctx,
	    const uint8_t *const buf, size_t sz);
void	whirlpool_end(struct whirlpool_ctx *const ctx, uint8_t *const buf);

__END_DECLS

#endif
