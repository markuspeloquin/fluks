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

#ifndef FLUKS_SERPENT_H
#define FLUKS_SERPENT_H

#include <features.h>
#include <stdint.h>

#ifdef __cplusplus
#	include <cstddef>
#else
#	include <stddef.h>
#endif

const size_t SERPENT_BLOCK = 16;

/** Key material not of correct length */
const int SERPENT_BAD_KEY_MAT = -1;

struct serpent_ctx {
      uint32_t	key[8];
      uint32_t	subkeys[33][4];
      uint16_t	keyLen;
};

__BEGIN_DECLS

int	serpent_init(struct serpent_ctx *ctx, const uint8_t *key,
	    size_t sz);

void	serpent_encrypt(const struct serpent_ctx *ctx, const uint8_t *in,
	    uint8_t *out);

void	serpent_decrypt(const struct serpent_ctx *ctx, const uint8_t *in,
	    uint8_t *out);

__END_DECLS

#endif
