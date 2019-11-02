/* Copyright (c) 2009-2010, Markus Peloquin <markus@cs.wisc.edu>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef FLUKS_CRYPT_HPP
#define FLUKS_CRYPT_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <boost/shared_array.hpp>

#include "luks.hpp"

namespace fluks {

class Cipher;
class Hash_function;

class Crypter {
	// CRYPTER! CRYPTER! CRYPTER!
protected:
	Crypter(const uint8_t *key, size_t sz_key, const Cipher_spec &spec);
	Crypter(const Crypter &rhs);
	Crypter &operator=(const Crypter &rhs);
	virtual ~Crypter() {}

	void swap(Crypter &rhs) {
		std::swap(_key, rhs._key);
		std::swap(_cipher, rhs._cipher);
		std::swap(_iv_hash, rhs._iv_hash);
		std::swap(_spec, rhs._spec);
		std::swap(_sz_key, rhs._sz_key);
	}

public:
	static std::shared_ptr<Crypter> create(const uint8_t *key,
	    size_t sz_key, const Cipher_spec &spec);

	/** Get the number of bytes required to encrypt data
	 *
	 * \param sz_plain	The size of the plaintext in bytes
	 * \return		The size buffer the ciphertext will require
	 */
	virtual size_t ciphertext_size(size_t sz_plain) const = 0;

	/** Encrypt data spanning across sectors
	 *
	 * \param[in] start_sector	The sector the data will start at
	 * \param[in] sz_sector	The size of the sectors
	 * \param[in] data	The data to encrypt
	 * \param[in] sz_plain	The size of the plaintext in bytes
	 * \param[out] out	The output buffer for the ciphertext. The
	 *	number of bytes required in the buffer can be obtained from
	 *	ciphertext_size()
	 * \throw Crypt_error	At present, only if CBC-CTS isn't possible
	 *	given the size of the plaintext
	 */
	void encrypt(uint32_t start_sector, size_t sz_sector,
	    const uint8_t *data, size_t sz_plain, uint8_t *out);

	/** Encrypt data spanning across blocks (cipher, not disk blocks)
	 *
	 * This encryption method uses only the cipher type and block modes
	 * specified in the object.
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initial vector. The size equals the block size
	 *	of the cipher. Ignored for ECB
	 * \param[in] in	Plaintext
	 * \param[in] sz_plain	The size of the plaintext
	 * \param[out] out	The ciphertext. Its size is obtainable from
	 *	ciphertext_size(), since some block modes may require padding
	 * \throw Crypt_error	At present, only if CBC-CTS isn't possible
	 *	given the size of the plaintext
	 */
	virtual void encrypt(Cipher *cipher, const uint8_t *iv,
	    const uint8_t *in, size_t sz_plain, uint8_t *out) = 0;

	/** Decrypt data spanning across sectors
	 *
	 * \param[in] start_sector	The sector the data starts at
	 * \param[in] sz_sector	The size of the sectors
	 * \param[in] data	The ciphertext to decrypt
	 * \param[in] sz_plain	The size of the plaintext in bytes
	 * \param[out] out	The output buffer for the plaintext. It is
	 *	assumed that you already know how long this should be
	 * \throw Crypt_error	At present, only if CBC-CTS isn't possible
	 *	given the size of the ciphertext
	 */
	void decrypt(uint32_t start_sector, size_t sz_sector,
	    const uint8_t *data, size_t sz_plain, uint8_t *out);

	/** Decrypt data spanning across blocks (cipher, not disk blocks)
	 *
	 * This decryption method uses only the cipher type and block modes
	 * specified in the object.
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initial vector. The size equals the block size
	 *	of the cipher. Ignored for ECB
	 * \param[in] in	Ciphertext
	 * \param[in] sz_plain	The size of the ciphertext
	 * \param[out] out	The plaintext. It is assumed that you already
	 *	know how long this should be
	 * \throw Crypt_error	At present, only if CBC-CTS isn't possible
	 *	given the size of the ciphertext
	 */
	virtual void decrypt(Cipher *cipher, const uint8_t *iv,
	    const uint8_t *in, size_t sz_plain, uint8_t *out) = 0;

protected:
	/** Convenience function for implementing ciphertext_size() for
	 * certain block modes.
	 *
	 * \param sz_plaintext	The size of the plaintext
	 * \return	The size required for the ciphertext after rounding
	 *	sz_plaintext up to the next multiple of the block size
	 */
	size_t ciphertext_size_ceil(size_t sz_plaintext) const;

private:

	boost::shared_array<uint8_t>	_key;
	std::shared_ptr<Cipher>		_cipher;
	std::shared_ptr<Hash_function>	_iv_hash;
	Cipher_spec			_spec;
	size_t				_sz_key;
};

class Crypter_cbc : public Crypter {
public:
	Crypter_cbc(const uint8_t *key, size_t sz_key,
	    const Cipher_spec &spec) :
		Crypter(key, sz_key, spec)
	{}

	Crypter_cbc(const Crypter_cbc &rhs) :
		Crypter(rhs)
	{}

	Crypter_cbc &operator=(const Crypter_cbc &rhs) {
		Crypter::operator=(rhs);
		return *this;
	}

	size_t ciphertext_size(size_t sz_plaintext) const override {
		return ciphertext_size_ceil(sz_plaintext);
	}

	/** Encrypt using Cyclic Block Chaining mode
	 *
	 * The final block is padded as necessary so that the size of the
	 * plaintext is a multiple of the cipher's block size.
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization Vector
	 * \param[in] in	Plaintext
	 * \param[in] sz_plain	The size of the plaintext
	 * \param[out] out	The ciphertext. Its size should be at least
	 *	\f$ \lceil \mathtt{sz\_plain}/C_\mathit{BS} \rceil \f$, where
	 *	\f$ C_\mathit{BS} \f$ is the block size of the cipher.
	 */
	void encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz_plain, uint8_t *out) noexcept override;

	/** Decrypt using Cyclic Block Chaining mode
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization Vector
	 * \param[in] in	Ciphertext
	 * \param[in] sz_plain	The size of the plaintext
	 * \param[out] out	The plaintext
	 */
	void decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz_plain, uint8_t *out) noexcept override;
};

class Crypter_cbc_cts : public Crypter {
public:
	Crypter_cbc_cts(const uint8_t *key, size_t sz_key,
	    const Cipher_spec &spec) :
		Crypter(key, sz_key, spec)
	{}

	Crypter_cbc_cts(const Crypter_cbc_cts &rhs) :
		Crypter(rhs)
	{}

	Crypter_cbc_cts &operator=(const Crypter_cbc_cts &rhs) {
		Crypter::operator=(rhs);
		return *this;
	}

	size_t ciphertext_size(size_t sz_plaintext) const override {
		return sz_plaintext;
	}

	/** Encrypt using Cyclic Block Chaining mode with Ciphertext Stealing
	 *
	 * The final block is padded as necessary so that the size of the
	 * plaintext is a multiple of the cipher's block size.
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization Vector
	 * \param[in] in	Plaintext
	 * \param[in] sz	The size of the plaintext/ciphertext, which
	 *	must be at least one full block size
	 * \param[out] out	The ciphertext
	 * \throw Crypt_error	If CBC-CTS isn't possible given the size of
	 *	the plaintext
	 */
	void encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz, uint8_t *out) override;

	/** Decrypt using Cyclic Block Chaining mode with Ciphertext Stealing
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization Vector
	 * \param[in] in	Ciphertext
	 * \param[in] sz	The size of the plaintext/ciphertext, which
	 *	must be at least one full block size
	 * \param[out] out	The plaintext. Its size should be at least
	 *	<code>sz_plain</code>.
	 * \throw Crypt_error	If CBC-CTS isn't possible given the size of
	 *	the ciphertext
	 */
	void decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz, uint8_t *out) override;
};

class Crypter_cfb : public Crypter {
public:
	Crypter_cfb(const uint8_t *key, size_t sz_key,
	    const Cipher_spec &spec) :
		Crypter(key, sz_key, spec)
	{}

	Crypter_cfb(const Crypter_cfb &rhs) :
		Crypter(rhs)
	{}

	Crypter_cfb &operator=(const Crypter_cfb &rhs) {
		Crypter::operator=(rhs);
		return *this;
	}

	size_t ciphertext_size(size_t sz_plaintext) const override {
		return ciphertext_size_ceil(sz_plaintext);
	}

	/** Encrypt using Cipher feedback
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization Vector
	 * \param[in] in	Plaintext
	 * \param[in] sz	The size of the plaintext and resulting
	 *	ciphertext
	 * \param[out] out	The ciphertext. It should be at least as big
	 *	as the plaintext buffer.
	 */
	void encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz, uint8_t *out) noexcept override;

	/** Decrypt using Cipher feedback
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization Vector
	 * \param[in] in	Ciphertext
	 * \param[in] sz	The size of the plaintext and ciphertext
	 * \param[out] out	Plaintext. It should be at least as big as the
	 *	ciphertext buffer.
	 */
	void decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz, uint8_t *out) noexcept override;
};

class Crypter_ctr : public Crypter {
public:
	Crypter_ctr(const uint8_t *key, size_t sz_key,
	    const Cipher_spec &spec) :
		Crypter(key, sz_key, spec)
	{}

	Crypter_ctr(const Crypter_ctr &rhs) :
		Crypter(rhs)
	{}

	Crypter_ctr &operator=(const Crypter_ctr &rhs) {
		Crypter::operator=(rhs);
		return *this;
	}

	size_t ciphertext_size(size_t sz_plaintext) const override {
		return sz_plaintext;
	}

	/** Encrypt using Counter mode
	 *
	 * The plaintext and the ciphertext will have the same length, as
	 * counter mode turns the block cipher into a sort of stream cipher.
	 * Encryption and decryption in counter mode are the same.
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization vector
	 * \param[in] in	Plaintext
	 * \param[in] sz	The size of the plaintext/ciphertext
	 * \param[out] out	The ciphertext. Its size should be at least
	 *	<code>sz</code>.
	 */
	void encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz, uint8_t *out) noexcept override;

	/** Decrypt using Counter mode
	 *
	 * \see encrypt()
	 */
	void decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz, uint8_t *out) noexcept override {
		encrypt(cipher, iv, in, sz, out);
	}
};

class Crypter_ecb : public Crypter {
public:
	Crypter_ecb(const uint8_t *key, size_t sz_key,
	    const Cipher_spec &spec) :
		Crypter(key, sz_key, spec)
	{}

	Crypter_ecb(const Crypter_ecb &rhs) :
		Crypter(rhs)
	{}

	Crypter_ecb &operator=(const Crypter_ecb &rhs) {
		Crypter::operator=(rhs);
		return *this;
	}

	size_t ciphertext_size(size_t sz_plaintext) const override {
		return ciphertext_size_ceil(sz_plaintext);
	}

	/** Encrypt using Electronic Code Book mode
	 *
	 * The most insecure of the encryption modes. The plaintext is padded
	 * so that its size is a multiple of the cipher's block size.
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization vector
	 * \param[in] in	Plaintext
	 * \param[in] sz_plain	The size of the plaintext
	 * \param[out] out	The ciphertext. Its size should be at least
	 *	\f$ \lceil \mathtt{sz\_plain}/C_\mathit{BS} \rceil \f$, where
	 *	\f$ C_\mathit{BS} \f$ is the block size of the cipher.
	 */
	void encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz_plain, uint8_t *out) noexcept override;

	/** Encrypt using Electronic Code Book mode
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization vector
	 * \param[in] in	Ciphertext
	 * \param[in] sz_plain	The size of the plaintext
	 * \param[out] out	The plaintext. Its size should be at least
	 *	<code>sz_plain</code>.
	 */
	void decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz_plain, uint8_t *out) noexcept override;
};

class Crypter_ofb : public Crypter {
public:
	Crypter_ofb(const uint8_t *key, size_t sz_key,
	    const Cipher_spec &spec) :
		Crypter(key, sz_key, spec)
	{}

	Crypter_ofb(const Crypter_ofb &rhs) :
		Crypter(rhs)
	{}

	Crypter_ofb &operator=(const Crypter_ofb &rhs) {
		Crypter::operator=(rhs);
		return *this;
	}

	size_t ciphertext_size(size_t sz_plaintext) const override {
		return sz_plaintext;
	}

	/** Encrypt using Output feedback
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization Vector
	 * \param[in] in	Plaintext
	 * \param[in] sz	The size of the plaintext and resulting
	 *	ciphertext
	 * \param[out] out	The ciphertext. It should be at least as big
	 *	as the plaintext buffer.
	 */
	void encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz, uint8_t *out) noexcept override;

	/** Decrypt using Output feedback
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization Vector
	 * \param[in] in	Ciphertext
	 * \param[in] sz	The size of the plaintext and ciphertext
	 * \param[out] out	Plaintext. It should be at least as big as the
	 *	ciphertext buffer.
	 */
	void decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz, uint8_t *out) noexcept override {
		encrypt(cipher, iv, in, sz, out);
	}
};

class Crypter_pcbc : public Crypter {
public:
	Crypter_pcbc(const uint8_t *key, size_t sz_key,
	    const Cipher_spec &spec) :
		Crypter(key, sz_key, spec)
	{}

	Crypter_pcbc(const Crypter_pcbc &rhs) :
		Crypter(rhs)
	{}

	Crypter_pcbc &operator=(const Crypter_pcbc &rhs) {
		Crypter::operator=(rhs);
		return *this;
	}

	size_t ciphertext_size(size_t sz_plaintext) const override {
		return ciphertext_size_ceil(sz_plaintext);
	}

	/** Encrypt using Propagating Cyclic Block Chaining mode
	 *
	 * The final block is padded as necessary so that the size of the
	 * plaintext is a multiple of the cipher's block size.
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization Vector
	 * \param[in] in	Plaintext
	 * \param[in] sz_plain	The size of the plaintext
	 * \param[out] out	The ciphertext. Its size should be at least
	 *	\f$ \lceil \mathtt{sz\_plain}/C_\mathit{BS} \rceil \f$, where
	 *	\f$ C_\mathit{BS} \f$ is the block size of the cipher.
	 */
	void encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz_plain, uint8_t *out) noexcept override;

	/** Decrypt using Propagating Cyclic Block Chaining mode
	 *
	 * \param[in] cipher	Block cipher
	 * \param[in] iv	Initialization Vector
	 * \param[in] in	Ciphertext
	 * \param[in] sz_plain	The size of the plaintext
	 * \param[out] out	The plaintext. Its size should be at least
	 *	<code>sz_plain</code>.
	 */
	void decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
	    size_t sz_plain, uint8_t *out) noexcept override;
};

}

#endif
