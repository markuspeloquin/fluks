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

#ifdef __cplusplus
// C++
#	include <cstddef>
#	include <tr1/cstdint>

// because I hate macros
const size_t WHIRLPOOL256_SZ_DIGEST = 32;
const size_t WHIRLPOOL384_SZ_DIGEST = 48;
const size_t WHIRLPOOL_SZ_DIGEST = 64;
const size_t WHIRLPOOL_SZ_BLOCK = 64;

#else 
/* C */
#	include <stddef.h>
#	include <stdint.h>

#	define WHIRLPOOL256_SZ_DIGEST	32
#	define WHIRLPOOL384_SZ_DIGEST	48
#	define WHIRLPOOL_SZ_DIGEST	64
#	define WHIRLPOOL_SZ_BLOCK	64
#endif

struct whirlpool_ctx {
	/* the hashing state */
	uint64_t	hash[WHIRLPOOL_SZ_DIGEST / 8];

	/* global number of hashed bits (256-bit counter) */
	uint8_t		bitLength[32];

	/* buffer of data to hash */
	uint8_t		buffer[WHIRLPOOL_SZ_BLOCK];

	/* current number of bits on the buffer */
	uint16_t	bufferBits;

	/* current (possibly incomplete) byte slot on the buffer */
	uint8_t		bufferPos;
};

__BEGIN_DECLS

/** Initialize/reset a whirlpool context.
 * \param ctx	The context.
 */
void	whirlpool_init(struct whirlpool_ctx *ctx);

/** Add append data to the data being hashed.
 * \param ctx	The context.
 * \param buf	The data to be appended (big endian).
 * \param sz	The size of the data in bytes.
 */
void	whirlpool_update(struct whirlpool_ctx *ctx,
	    const uint8_t *buf, size_t sz);

/** Mark the end of the hashed data and return the digest.
 * \param[in] ctx	The context.
 * \param[out] buf	The destination buffer of the digest.
 */
void	whirlpool_end(struct whirlpool_ctx *ctx,
	    uint8_t buf[WHIRLPOOL_SZ_DIGEST]);

__END_DECLS

#endif
