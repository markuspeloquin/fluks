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

#include <tr1/memory>

#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/cast.h>

#include "cast6.h"
#include "luks.hpp"
#include "serpent.h"
#include "twofish.h"

namespace fluks {


enum crypt_direction { DIR_NONE, DIR_ENCRYPT, DIR_DECRYPT };

/** En/Decrypt a block of data */
class Crypt {
	// CRYPTER! CRYPTER! CRYPTER!
public:
	/** Create an encryption or decryption object
	 *
	 * \param type	The cipher to use
	 * \return	An object to en/decrypt with.  It's meant to be used
	 *	with the XXX_encrypt() and XXX_decrypt() functions.
	 */
	static std::tr1::shared_ptr<Crypt> create(enum cipher_type type);

	virtual ~Crypt() throw () {}

	/** Set the direction of encryption and the key
	 *
	 * \param key		The encryption key
	 * \param sz_key	The size of the encryption key in bytes
	 * \param Crypt_error	Probably the key size is bad
	 */
	virtual void init(const uint8_t *key, size_t sz_key)
	    throw (Crypt_error) = 0;

	/** Encrypt a block of data
	 *
	 * \param in	Plaintext
	 * \param out	Ciphertext, usually cannot be equal to <code>in</code>.
	 * \throw Crypt_error	This will occur if the init() function was
	 *	not first called or if <code>in<code> cannot be equal to
	 *	</code>out</code>.
	 */
	virtual void encrypt(const uint8_t *in, uint8_t *out)
	    throw (Crypt_error) = 0;

	/** Decrypt a block of data
	 *
	 * \param in	Ciphertext
	 * \param out	Plaintext, usually cannot be equal to <code>in</code>.
	 * \throw Crypt_error	This will occur if the init() function was
	 *	not first called or if <code>in<code> cannot be equal to
	 *	</code>out</code>.
	 */
	virtual void decrypt(const uint8_t *in, uint8_t *out)
	    throw (Crypt_error) = 0;

	/** Get the block size of the cipher
	 * 
	 * \return	The block size in bytes.
	 */
	virtual size_t block_size() const throw () = 0;
};

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
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization Vector
 * \param[in] in	Plaintext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The ciphertext.  Its size should be at least
 *	<code>ceil(sz_plain/B)</code>, where <code>B</code> is the block
 *	size of the cipher.
 */
void		cbc_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Decrypt using Cyclic Block Chaining mode
 *
 * \param[in] crypter	Block decrypter
 * \param[in] iv	Initialization Vector
 * \param[in] in	Ciphertext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The plaintext.  Its size should be at least
 *	<code>sz_plain</code>.
 */
void		cbc_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Encrypt using Cipher feedback
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization Vector
 * \param[in] in	Plaintext
 * \param[in] sz	The size of the plaintext and resulting ciphertext
 * \param[out] out	The ciphertext.  It should be at least as big as the
 *	plaintext buffer.
 */
void		cfb_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Decrypt using Cipher feedback
 *
 * \param[in] crypter	Block decrypter
 * \param[in] iv	Initialization Vector
 * \param[in] in	Ciphertext
 * \param[in] sz	The size of the plaintext and ciphertext
 * \param[out] out	Plaintext.  It should be at least as big as the
 *	ciphertext buffer.
 */
void		cfb_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Encrypt using Counter mode
 *
 * The plaintext and the ciphertext will have the same length, as counter
 * mode turns the block cipher into a sort of stream cipher.  Encryption
 * and decryption in counter mode are the same.
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization vector
 * \param[in] in	Plaintext
 * \param[in] sz	The size of the plaintext/ciphertext
 * \param[out] out	The ciphertext.  Its size should be at least
 *	<code>sz</code>.
 */
void		ctr_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Decrypt using Counter mode
 *
 * The plaintext and the ciphertext will have the same length, as counter
 * mode turns the block cipher into a sort of stream cipher.  Encryption
 * and decryption in counter mode are the same.
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization vector
 * \param[in] in	Ciphertext
 * \param[in] sz	The size of the plaintext/ciphertext
 * \param[out] out	The plaintext.  Its size should be at least
 *	<code>sz</code>.
 */
inline void	ctr_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Encrypt using Electronic Code Book mode
 *
 * The most insecure of the encryption modes.  The plaintext is padded so
 * that its size is a multiple of the cipher's block size.
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization vector
 * \param[in] in	Plaintext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The ciphertext.  Its size should be at least
 *	<code>ceil(sz_plain/B)</code>, where <code>B</code> is the block
 *	size of the cipher.
 */
void		ecb_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Encrypt using Electronic Code Book mode
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization vector
 * \param[in] in	Ciphertext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The plaintext.  Its size should be at least
 *	<code>sz_plain</code>.
 */
void		ecb_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Encrypt using Output feedback
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization Vector
 * \param[in] in	Plaintext
 * \param[in] sz	The size of the plaintext and resulting ciphertext
 * \param[out] out	The ciphertext.  It should be at least as big as the
 *	plaintext buffer.
 */
void		ofb_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Decrypt using Output feedback
 *
 * \param[in] crypter	Block decrypter
 * \param[in] iv	Initialization Vector
 * \param[in] in	Ciphertext
 * \param[in] sz	The size of the plaintext and ciphertext
 * \param[out] out	Plaintext.  It should be at least as big as the
 *	ciphertext buffer.
 */
void		ofb_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Encrypt using Propagating Cyclic Block Chaining mode
 *
 * The final block is padded as necessary so that the size of the plaintext
 * is a multiple of the cipher's block size.
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization Vector
 * \param[in] in	Plaintext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The ciphertext.  Its size should be at least
 *	<code>ceil(sz_plain/B)</code>, where <code>B</code> is the block
 *	size of the cipher.
 */
void		pcbc_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Decrypt using Propagating Cyclic Block Chaining mode
 *
 * \param[in] crypter	Block decrypter
 * \param[in] iv	Initialization Vector
 * \param[in] in	Ciphertext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The plaintext.  Its size should be at least
 *	<code>sz_plain</code>.
 */
void		pcbc_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);


// the encryption and decryption work the same for these
inline void
ctr_decrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz, uint8_t *out)
{	ctr_encrypt(crypter, iv, in, sz, out); }
inline void
ofb_decrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz, uint8_t *out)
{	ofb_encrypt(crypter, iv, in, sz, out); }


/** AES encryption, using OpenSSL */
class Crypt_aes : public Crypt {
public:
	Crypt_aes() : _init(false) {}
	~Crypt_aes() throw () {}

	void init(const uint8_t *key, size_t sz) throw ()
	{
		_key_data.reset(new uint8_t[sz]);
		std::copy(key, key + sz, _key_data.get());
		_sz = sz;
		_dir = DIR_NONE;
		_init = true;
	}
	void encrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no en/decryption key set");
		if (in == out)
			// TODO see if this is necessary for AES
			throw Crypt_error("for AES, input and output buffers "
			    "should be different");
		if (_dir != DIR_ENCRYPT) {
			if (!AES_set_encrypt_key(_key_data.get(), _sz * 8,
			    &_key))
				throw Ssl_crypt_error();
			_dir = DIR_ENCRYPT;
		}
		AES_encrypt(in, out, &_key);
	}
	void decrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no en/decryption key set");
		if (in == out)
			// TODO see if this is necessary for AES
			throw Crypt_error("for AES, input and output buffers "
			    "should be different");
		if (_dir != DIR_DECRYPT) {
			if (!AES_set_decrypt_key(_key_data.get(), _sz * 8,
			    &_key))
				throw Ssl_crypt_error();
			_dir = DIR_DECRYPT;
		}
		AES_decrypt(in, out, &_key);
	}
	size_t block_size() const throw ()
	{	return AES_BLOCK_SIZE; }

private:
	AES_KEY			_key;
	boost::scoped_array<uint8_t> _key_data;
	size_t			_sz;
	enum crypt_direction	_dir;
	bool			_init;
};

class Crypt_blowfish : public Crypt {
public:
	Crypt_blowfish() : _init(false) {}
	~Crypt_blowfish() throw () {}

	void init(const uint8_t *key, size_t sz) throw ()
	{
		_init = true;
		BF_set_key(&_key, sz, key);
	}
	void encrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no encryption key set");
		if (in == out)
			// TODO see if this is necessary for blowfish
			throw Crypt_error("for Blowfish, input and output "
			    "buffers should be different");
		BF_ecb_encrypt(in, out, &_key, BF_ENCRYPT);
	}
	void decrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no decryption key set");
		if (in == out)
			// TODO see if this is necessary for blowfish
			throw Crypt_error("for Blowfish, input and output "
			    "buffers should be different");
		BF_ecb_encrypt(in, out, &_key, BF_DECRYPT);
	}
	size_t block_size() const throw ()
	{	return BF_BLOCK; }

private:
	BF_KEY			_key;
	bool			_init;
};

class Crypt_cast5 : public Crypt {
public:
	Crypt_cast5() : _init(false) {}
	~Crypt_cast5() throw () {}

	void init(const uint8_t *key, size_t sz) throw ()
	{
		_init = true;
		CAST_set_key(&_key, sz, key);
	}
	void encrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no encryption key set");
		if (in == out)
			// TODO see if this is necessary for cast5
			throw Crypt_error("for CAST5, input and output "
			    "buffers should be different");
		CAST_ecb_encrypt(in, out, &_key, CAST_ENCRYPT);
	}
	void decrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no decryption key set");
		if (in == out)
			// TODO see if this is necessary for cast5
			throw Crypt_error("for CAST5, input and output "
			    "buffers should be different");
		CAST_ecb_encrypt(in, out, &_key, CAST_DECRYPT);
	}
	size_t block_size() const throw ()
	{	return CAST_BLOCK; }

private:
	CAST_KEY		_key;
	bool			_init;
};

class Crypt_cast6 : public Crypt {
public:
	Crypt_cast6() : _init(false) {}
	~Crypt_cast6() throw () {}

	void init(const uint8_t *key, size_t sz) throw (Crypt_error)
	{
		_init = true;
		if (!cast6_init(&_ctx, key, sz))
			throw Crypt_error("bad key size");
	}
	void encrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no encryption key set");
		// it's fine if in==out
		cast6_encrypt(&_ctx, in, out);
	}
	void decrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no decryption key set");
		// it's fine if in==out
		cast6_decrypt(&_ctx, in, out);
	}
	size_t block_size() const throw ()
	{	return CAST6_BLOCK; }

private:
	struct cast6_ctx	_ctx;
	bool			_init;
};

class Crypt_serpent : public Crypt {
public:
	Crypt_serpent() : _init(false) {}
	~Crypt_serpent() throw () {}

	void init(const uint8_t *key, size_t sz) throw (Crypt_error)
	{
		_init = true;
		if (serpent_init(&_ctx, key, sz) == SERPENT_BAD_KEY_MAT)
			throw Crypt_error("bad key size");
	}
	void encrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no encryption key set");
		// it's fine if in==out
		serpent_encrypt(&_ctx, in, out);
	}
	void decrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no decryption key set");
		// it's fine if in==out
		serpent_decrypt(&_ctx, in, out);
	}
	size_t block_size() const throw ()
	{	return SERPENT_BLOCK; }

private:
	struct serpent_ctx	_ctx;
	bool			_init;
};

class Crypt_twofish : public Crypt {
public:
	Crypt_twofish() : _init(false) {}
	~Crypt_twofish() throw () {}

	void init(const uint8_t *key, size_t sz) throw ()
	{
		_init = true;
		twofish_init(&_ctx, key, sz);
	}
	void encrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no encryption key set");
		// it's fine if in==out
		twofish_encrypt(&_ctx, in, out);
	}
	void decrypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error("no decryption key set");
		// it's fine if in==out
		twofish_decrypt(&_ctx, in, out);
	}
	size_t block_size() const throw ()
	{	return TWOFISH_BLOCK; }

private:
	struct twofish_ctx	_ctx;
	bool			_init;
};

}

#endif
