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

#ifndef FLUKS_TWOFISH_H
#define FLUKS_TWOFISH_H

#include <features.h>

#ifdef __cplusplus
#	include <cstddef>
#	include <tr1/cstdint>

	const size_t TWOFISH_KEYMIN = 16;
	const size_t TWOFISH_KEYMAX = 32;
	const size_t TWOFISH_KEYSTEP = 8;
	const size_t TWOFISH_BLOCK = 16;
#else
#	include <stdbool.h>
#	include <stddef.h>
#	include <stdint.h>

#	define TWOFISH_KEYMIN 16
#	define TWOFISH_KEYMAX 32
#	define TWOFISH_KEYSTEP 8
#	define TWOFISH_BLOCK 16
#endif


struct twofish_ctx {
	uint32_t K[40];
	uint32_t QF[4][256];
};

__BEGIN_DECLS

/** Set the %key for en/decryption
 *
 * \param key		Twofish %key structure
 * \param keydata	The %key for en/decryption
 * \param sz		The size in bytes of the %key
 * \retval true iff key size is fine
 */
bool	twofish_init(struct twofish_ctx *key, const uint8_t *keydata,
	    size_t sz);

/** Encrypt a block of plaintext
 *
 * Both the input and output buffers should be of size
 * <code>TWOFISH_BLOCK</code>.
 *
 * \param[in] key	The encryption %key
 * \param[in] in	The plaintext
 * \param[out] out	The ciphertext buffer
 */
void	twofish_encrypt(struct twofish_ctx *key, const uint8_t *in,
	    uint8_t *out);

/** Decrypt a block of ciphertext
 *
 * Both the input and output buffers should be of size
 * <code>TWOFISH_BLOCK</code>.
 *
 * \param[in] key	The decryption %key
 * \param[in] in	The ciphertext
 * \param[out] out	The plaintext buffer
 */
void	twofish_decrypt(struct twofish_ctx *key, const uint8_t *in,
	    uint8_t *out);

__END_DECLS

#endif
