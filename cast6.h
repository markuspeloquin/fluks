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

#ifndef CAST6_H
#define CAST6_H

#include <features.h>
#include <stdint.h>

#ifdef __cplusplus
#	include <cstddef>
namespace fluks {
#else
#	include <stdbool.h>
#	include <stddef.h>
#endif

/** Size of a CAST-256 block (bytes) */
static const size_t CAST6_BLOCK = 16;

/** Minimum size of a CAST-256 key (bytes) */
static const size_t CAST6_KEY_MIN = 16;

/** Maximum size of a CAST-256 key (bytes) */
static const size_t CAST6_KEY_MAX = 32;

/** CAST-256 keys are all
 * <code>CAST6_KEY_MIN + n * CAST6_KEY_STEP</code> bytes */
static const size_t CAST6_KEY_STEP = 4;

struct cast6_ctx {
	uint32_t	Km[12][4];
	uint8_t		Kr[12][4];
};

__BEGIN_DECLS

/** Initialize a CAST-256 context
 *
 * \param ctx		Uninitialized structure
 * \param key		Private key
 * \param sz		The size in bytes of the key.  Valid sizes are
 *	16, 20, 24, 28, 32
 * \retval false	The key size is invalid
 */
bool	cast6_init(struct cast6_ctx *ctx, const uint8_t *key, uint8_t sz);

/** Encrypt a block of data
 *
 * \param[in] ctx		Context
 * \param[in] plaintext		Data to encrypt
 * \param[out] ciphertext	Encrypted data
 */
void	cast6_encrypt(const struct cast6_ctx *ctx,
	    const uint8_t plaintext[CAST6_BLOCK],
	    uint8_t ciphertext[CAST6_BLOCK]);

/** Decrypt a block of data
 *
 * \param[in] ctx		Context
 * \param[in] ciphertext	Data to decrypt
 * \param[out] plaintext	Decrypted data
 */
void	cast6_decrypt(const struct cast6_ctx *ctx,
	    const uint8_t ciphertext[CAST6_BLOCK],
	    uint8_t plaintext[CAST6_BLOCK]);

__END_DECLS

#ifdef __cplusplus
} // end fluks
#endif

#endif
