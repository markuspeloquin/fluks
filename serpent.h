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
const size_t SERPENT_KEYMIN = 16;
const size_t SERPENT_KEYMAX = 32;
const size_t SERPENT_KEYSTEP = 8;

/** Key material not of correct length */
enum serpent_return {
	SERPENT_BAD_KEY_MAT = -1,
	SERPENT_OKAY = 0
};

struct serpent_ctx {
      uint32_t	subkeys[33][4];
};

__BEGIN_DECLS

enum serpent_return
	serpent_init(struct serpent_ctx *ctx,
	    const uint8_t *key, size_t sz);

void	serpent_encrypt(const struct serpent_ctx *ctx,
	    const uint8_t plaintext[SERPENT_BLOCK],
	    uint8_t ciphertext[SERPENT_BLOCK]);

void	serpent_decrypt(const struct serpent_ctx *ctx,
	    const uint8_t ciphertext[SERPENT_BLOCK],
	    uint8_t plaintext[SERPENT_BLOCK]);

__END_DECLS

#endif
