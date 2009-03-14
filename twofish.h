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
#include <stdint.h>

#ifdef __cplusplus
#	include <cstddef>
#else
#	include <stddef.h>
#endif

const size_t TWOFISH_BLOCK = 16;

struct twofish_key {
	uint32_t K[40];
	uint32_t QF[4][256];
};

__BEGIN_DECLS

/** Set the %key for en/decryption
 *
 * \param key		Twofish %key structure
 * \param keydata	The %key for en/decryption
 * \param sz		The size in bytes of the %key
 */
void	twofish_set_key(struct twofish_key *key, const uint8_t *keydata,
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
void	twofish_encrypt(struct twofish_key *key, const uint8_t *in,
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
void	twofish_decrypt(struct twofish_key *key, const uint8_t *in,
	    uint8_t *out);

__END_DECLS

#endif
