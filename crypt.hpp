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

#ifndef FLUKS_CRYPT_HPP
#define FLUKS_CRYPT_HPP

#include <stdint.h>

#include <cstddef>

#include "luks.hpp"

namespace fluks {

class Cipher;

/** Get the number of bytes required to encrypt data
 *
 * \param cipher	The cipher to encrypt with
 * \param block_mode	The block mode to encrypt with
 * \param sz_data	The size of the plaintext in bytes
 * \return		The size buffer the ciphertext will require
 */
size_t	ciphertext_size(enum cipher_type cipher, enum block_mode block_mode,
	    size_t sz_data);

/** Encrypt a span of data
 *
 * \param cipher	The cipher to encrypt with
 * \param block_mode	The block mode to encrypt with
 * \param iv_mode	The IV generation mode
 * \param iv_hash	The hash function to use for ESSIV, whose block size
 *	is a possible key size of the cipher.
 * \param start_sector	The sector the data will start at
 * \param sz_sector	The size of the sectors
 * \param key		The key to encrypt the data with
 * \param sz_key	The size of the key in bytes
 * \param data		The data to encrypt
 * \param sz_data	The size of the plaintext in bytes
 * \param[out] out	The output buffer for the ciphertext.  The number
 *	of bytes required in the buffer can be obtained from
 *	ciphertext_size().
 */
void	encrypt(enum cipher_type cipher, enum block_mode block_mode,
	    enum iv_mode iv_mode, enum hash_type iv_hash,
	    uint32_t start_sector, size_t sz_sector,
	    const uint8_t *key, size_t sz_key,
	    const uint8_t *data, size_t sz_data,
	    uint8_t *out);

/** Decrypt a span of data
 *
 * \param cipher	The cipher that was used
 * \param block_mode	The block mode that was used
 * \param iv_mode	The IV generation mode that was used
 * \param iv_hash	The hash function used for ESSIV
 * \param start_sector	The sector the data starts at
 * \param sz_sector	The size of the sectors
 * \param key		The key used to encrypt the data
 * \param sz_key	The size of the key in bytes
 * \param data		The ciphertext to decrypt
 * \param sz_data	The size of the plaintext in bytes
 * \param[out] out	The output buffer for the plaintext
 */
void	decrypt(enum cipher_type cipher, enum block_mode block_mode,
	    enum iv_mode iv_mode, enum hash_type iv_hash,
	    uint32_t start_sector, size_t sz_sector,
	    const uint8_t *key, size_t sz_key,
	    const uint8_t *data, size_t sz_data,
	    uint8_t *out);

/** Encrypt using Cyclic Block Chaining mode
 *
 * The final block is padded as necessary so that the size of the plaintext
 * is a multiple of the cipher's block size.
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization Vector
 * \param[in] in	Plaintext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The ciphertext.  Its size should be at least
 *	<code>ceil(sz_plain/B)</code>, where <code>B</code> is the block
 *	size of the cipher.
 */
void		cbc_encrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Decrypt using Cyclic Block Chaining mode
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization Vector
 * \param[in] in	Ciphertext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The plaintext.  Its size should be at least
 *	<code>sz_plain</code>.
 */
void		cbc_decrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Encrypt using Cipher feedback
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization Vector
 * \param[in] in	Plaintext
 * \param[in] sz	The size of the plaintext and resulting ciphertext
 * \param[out] out	The ciphertext.  It should be at least as big as the
 *	plaintext buffer.
 */
void		cfb_encrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Decrypt using Cipher feedback
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization Vector
 * \param[in] in	Ciphertext
 * \param[in] sz	The size of the plaintext and ciphertext
 * \param[out] out	Plaintext.  It should be at least as big as the
 *	ciphertext buffer.
 */
void		cfb_decrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Encrypt using Counter mode
 *
 * The plaintext and the ciphertext will have the same length, as counter
 * mode turns the block cipher into a sort of stream cipher.  Encryption
 * and decryption in counter mode are the same.
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization vector
 * \param[in] in	Plaintext
 * \param[in] sz	The size of the plaintext/ciphertext
 * \param[out] out	The ciphertext.  Its size should be at least
 *	<code>sz</code>.
 */
void		ctr_encrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Decrypt using Counter mode
 *
 * The plaintext and the ciphertext will have the same length, as counter
 * mode turns the block cipher into a sort of stream cipher.  Encryption
 * and decryption in counter mode are the same.
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization vector
 * \param[in] in	Ciphertext
 * \param[in] sz	The size of the plaintext/ciphertext
 * \param[out] out	The plaintext.  Its size should be at least
 *	<code>sz</code>.
 */
inline void	ctr_decrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Encrypt using Electronic Code Book mode
 *
 * The most insecure of the encryption modes.  The plaintext is padded so
 * that its size is a multiple of the cipher's block size.
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization vector
 * \param[in] in	Plaintext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The ciphertext.  Its size should be at least
 *	<code>ceil(sz_plain/B)</code>, where <code>B</code> is the block
 *	size of the cipher.
 */
void		ecb_encrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Encrypt using Electronic Code Book mode
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization vector
 * \param[in] in	Ciphertext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The plaintext.  Its size should be at least
 *	<code>sz_plain</code>.
 */
void		ecb_decrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Encrypt using Output feedback
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization Vector
 * \param[in] in	Plaintext
 * \param[in] sz	The size of the plaintext and resulting ciphertext
 * \param[out] out	The ciphertext.  It should be at least as big as the
 *	plaintext buffer.
 */
void		ofb_encrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Decrypt using Output feedback
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization Vector
 * \param[in] in	Ciphertext
 * \param[in] sz	The size of the plaintext and ciphertext
 * \param[out] out	Plaintext.  It should be at least as big as the
 *	ciphertext buffer.
 */
void		ofb_decrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Encrypt using Propagating Cyclic Block Chaining mode
 *
 * The final block is padded as necessary so that the size of the plaintext
 * is a multiple of the cipher's block size.
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization Vector
 * \param[in] in	Plaintext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The ciphertext.  Its size should be at least
 *	<code>ceil(sz_plain/B)</code>, where <code>B</code> is the block
 *	size of the cipher.
 */
void		pcbc_encrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Decrypt using Propagating Cyclic Block Chaining mode
 *
 * \param[in] cipher	Block cipher
 * \param[in] iv	Initialization Vector
 * \param[in] in	Ciphertext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The plaintext.  Its size should be at least
 *	<code>sz_plain</code>.
 */
void		pcbc_decrypt(Cipher *cipher, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

}

#include "crypt_private.hpp"

#endif
