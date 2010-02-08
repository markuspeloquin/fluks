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

#include <cstddef>
#include <tr1/cstdint>

#include "luks.hpp"

namespace fluks {

class Cipher;
class Hash_function;

class Crypter {
	// CRYPTER! CRYPTER! CRYPTER!
public:
	Crypter(const uint8_t *key, size_t sz_key, const Cipher_spec &spec);

	/** Get the number of bytes required to encrypt data
	 *
	 * \param sz_data	The size of the plaintext in bytes
	 * \return		The size buffer the ciphertext will require
	 */
	size_t ciphertext_size(size_t sz_data) const;

	/** Encrypt data spanning across sectors
	 *
	 * \param[in] start_sector	The sector the data will start at
	 * \param[in] sz_sector	The size of the sectors
	 * \param[in] data		The data to encrypt
	 * \param[in] sz_data	The size of the plaintext in bytes
	 * \param[out] out	The output buffer for the ciphertext.  The
	 *	number of bytes required in the buffer can be obtained from
	 *	ciphertext_size()
	 */
	void encrypt(uint32_t start_sector, size_t sz_sector,
	    const uint8_t *data, size_t sz_data, uint8_t *out);

	/** Encrypt data spanning across blocks (cipher, not disk blocks)
	 *
	 * This encryption method uses only the cipher type and block modes
	 * specified in the object.
	 *
	 * \param[in] iv	Initial vector.  The size equals the block
	 *	size of the cipher.  Ignored for ECB
	 * \param[in] in	Plaintext
	 * \param[in] sz_plain	The size of the plaintext
	 * \param[out] out	The ciphertext.  Its size is obtainable from
	 *	ciphertext_size(), since some block modes may require padding
	 */
	void encrypt(const uint8_t *iv, const uint8_t *in, size_t sz_plain,
	    uint8_t *out)
	{
		get_encrypt_fn()(_cipher.get(), iv, in, sz_plain, out);
	}

	/** Decrypt data spanning across sectors
	 *
	 * \param[in] start_sector	The sector the data starts at
	 * \param[in] sz_sector	The size of the sectors
	 * \param[in] data		The ciphertext to decrypt
	 * \param[in] sz_data	The size of the plaintext in bytes
	 * \param[out] out	The output buffer for the plaintext.  It is
	 *	assumed that you already know how long this should be
	 */
	void decrypt(uint32_t start_sector, size_t sz_sector,
	    const uint8_t *data, size_t sz_data, uint8_t *out);

	/** Decrypt data spanning across blocks (cipher, not disk blocks)
	 *
	 * This decryption method uses only the cipher type and block modes
	 * specified in the object.
	 *
	 * \param[in] iv	Initial vector.  The size equals the block
	 *	size of the cipher.  Ignored for ECB
	 * \param[in] in	Ciphertext
	 * \param[in] sz_plain	The size of the ciphertext
	 * \param[out] out	The plaintext.  It is assumed that you already
	 *	know how long this should be
	 */
	void decrypt(const uint8_t *iv, const uint8_t *in, size_t sz_plain,
	    uint8_t *out)
	{
		get_decrypt_fn()(_cipher.get(), iv, in, sz_plain, out);
	}

private:
	typedef void (*crypt_fn)(Cipher *, const uint8_t *, const uint8_t *,
	    size_t, uint8_t *);

	crypt_fn get_decrypt_fn() const;
	crypt_fn get_encrypt_fn() const;

	// disallow copying
	Crypter(const Crypter &x) : _spec(x._spec) {Assert(0,"");}
	void operator=(const Crypter &) {Assert(0,"");}

	boost::scoped_array<uint8_t>		_key;
	std::tr1::shared_ptr<Cipher>		_cipher;
	std::tr1::shared_ptr<Hash_function>	_iv_hash;
	Cipher_spec				_spec;
	size_t					_sz_key;
};

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
