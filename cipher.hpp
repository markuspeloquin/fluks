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

#ifndef FLUKS_CIPHER_HPP
#define FLUKS_CIPHER_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/cast.h>

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_CAMELLIA
#	include <openssl/camellia.h>
#endif

#include "cast6.h"
#include "errors.hpp"
#include "luks.hpp"
#include "serpent.h"
#include "twofish.h"

namespace fluks {

enum class crypt_direction { NONE, ENCRYPT, DECRYPT };

/** Information for a cipher function */
class Cipher_traits {
public:
	/** Required for storage in a vector, but isn't otherwise used. */
	Cipher_traits() {}
	/** Create a cipher traits object.
	 * \param name		The cipher's name
	 * \param max_key	The largest key size
	 * \param min_key	The smallest key size
	 * \param key_step	The size difference between every consective
	 *	pair of key sizes.
	 * \param sz_blk	The block size
	 * \param version	The version of LUKS required, or 0 if not LUKS.
	 */
	Cipher_traits(const std::string &name,
	    uint16_t min_key, uint16_t max_key, uint16_t key_step,
	    uint16_t sz_blk, uint16_t version);

	/** Get information for a cipher
	 * \return Cipher information, or <code>nullptr</code> if nonexistent.
	 */
	static const Cipher_traits *traits(cipher_type type);
	/** Get the type of a cipher
	 * \return The enum of the cipher
	 */
	static cipher_type type(const std::string &name);
	/** Get all types that fluks supports
	 * \return The supported types
	 */
	static const std::vector<cipher_type> &types();

	/** Get all types that fluks supports
	 * \param out Destination of supported types
	 */
	template <typename Out>
	static void types(Out out) {
		const std::vector<cipher_type> &t = types();
		std::copy(t.begin(), t.end(), out);
	}

	std::string name; /**< The cipher's name */
	std::vector<uint16_t> key_sizes; /**< The possible key sizes */
	uint16_t block_size; /**< The block size */
	/** The LUKS version required, or 0 if not LUKS */
	uint16_t luks_version;
};

/** En/Decrypt a block of data */
class Cipher {
protected:
	/** Set up the properties of the cipher function
	 * \param type The cipher type
	 */
	Cipher(cipher_type type) :
		_traits(Cipher_traits::traits(type))
	{}

public:
	/** Create an encryption or decryption object
	 *
	 * \param type	The cipher to use
	 * \return	An object to en/decrypt with. It's meant to be used
	 *	with the *_encrypt() and *_decrypt() functions.
	 */
	static std::shared_ptr<Cipher> create(cipher_type type);

	virtual ~Cipher() noexcept {}

	/** Set the the key
	 *
	 * \param key		The encryption key
	 * \param sz_key	The size of the encryption key in bytes
	 * \throw Crypt_error	Probably the key size is bad
	 */
	virtual void init(const uint8_t *key, size_t sz_key)
	    noexcept(false) = 0;

	/** Encrypt a block of data
	 *
	 * \param in	Plaintext
	 * \param out	Ciphertext, usually cannot be equal to <code>in</code>.
	 * \throw Crypt_error	This will occur if the init() function was
	 *	not first called or if <code>in<code> cannot be equal to
	 *	</code>out</code>.
	 */
	virtual void encrypt(const uint8_t *in, uint8_t *out)
	    noexcept(false) = 0;

	/** Decrypt a block of data
	 *
	 * \param in	Ciphertext
	 * \param out	Plaintext, usually cannot be equal to <code>in</code>.
	 * \throw Crypt_error	This will occur if the init() function was
	 *	not first called or if <code>in<code> cannot be equal to
	 *	</code>out</code>.
	 */
	virtual void decrypt(const uint8_t *in, uint8_t *out)
	    noexcept(false) = 0;

	/** Get information on the current cipher
	 *
	 * \return	The block size in bytes.
	 */
	const Cipher_traits *traits() const {
		return _traits;
	}

private:
	const Cipher_traits *_traits;
};

/** The Rijndael cipher. Published in 1998. AES winner, with CRYPTREC, NESSIE,
 * NSA certifications. OpenSSL implementation. */
class Cipher_aes : public Cipher {
public:
	Cipher_aes() : Cipher(cipher_type::AES), _init(false) {}
	~Cipher_aes() noexcept {}

	void init(const uint8_t *key, size_t sz) noexcept {
		// Rijndael keys are set up differently depending if they're
		// being used for encryption or decryption; the two choices
		// are (1) store two AES contexts or (2) store one context
		// and a copy of the key; (1) uses more memory than (2), and
		// (1) uses less CPU than (2) if the Cipher_aes object
		// doesn't get repurposed more than once
		_key_data.reset(new uint8_t[sz]);
		std::copy(key, key + sz, _key_data.get());
		_sz = sz;
		_dir = crypt_direction::NONE;
		_init = true;
	}

	void encrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no en/decryption key set");
		if (_dir != crypt_direction::ENCRYPT) {
			if (AES_set_encrypt_key(_key_data.get(), _sz * 8,
			    &_key) < 0)
				throw Ssl_crypt_error();
			_dir = crypt_direction::ENCRYPT;
		}
		AES_encrypt(in, out, &_key);
	}

	void decrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no en/decryption key set");
		if (_dir != crypt_direction::DECRYPT) {
			if (AES_set_decrypt_key(_key_data.get(), _sz * 8,
			    &_key) < 0)
				throw Ssl_crypt_error();
			_dir = crypt_direction::DECRYPT;
		}
		AES_decrypt(in, out, &_key);
	}

private:
	AES_KEY		_key;
	std::unique_ptr<uint8_t> _key_data;
	size_t		_sz;
	crypt_direction	_dir;
	bool		_init;
};

/** The Blowfish cipher. Published in 1993. OpenSSL implementation. */
class Cipher_blowfish : public Cipher {
public:
	Cipher_blowfish() : Cipher(cipher_type::BLOWFISH), _init(false) {}
	~Cipher_blowfish() noexcept {}

	void init(const uint8_t *key, size_t sz) noexcept(false) {
		// BF_set_key() doesn't check its input size (or silently
		// fixes it)
		const std::vector<uint16_t> &sizes =
		    Cipher_traits::traits(cipher_type::BLOWFISH)->key_sizes;
		if (!std::binary_search(sizes.begin(), sizes.end(), sz))
			throw Crypt_error("bad key size");

		_init = true;
		BF_set_key(&_key, sz, key);
	}

	void encrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no encryption key set");
		BF_ecb_encrypt(in, out, &_key, BF_ENCRYPT);
	}

	void decrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no decryption key set");
		BF_ecb_encrypt(in, out, &_key, BF_DECRYPT);
	}

private:
	BF_KEY			_key;
	bool			_init;
};

#ifndef OPENSSL_NO_CAMELLIA
/** The Camellia cipher. Published in 2000. CRYPTREC, NESSIE certification.
 * OpenSSL implementation. */
class Cipher_camellia : public Cipher {
public:
	Cipher_camellia() : Cipher(cipher_type::CAMELLIA), _init(false) {}
	~Cipher_camellia() noexcept {}

	void init(const uint8_t *key, size_t sz) noexcept(false) {
		if (Camellia_set_key(key, sz*8, &_ctx) < 0)
			throw Crypt_error("bad key size");
		_init = true;
	}

	void encrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no encryption key set");
		Camellia_encrypt(in, out, &_ctx);
	}

	void decrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no decryption key set");
		Camellia_decrypt(in, out, &_ctx);
	}

private:
	CAMELLIA_KEY		_ctx;
	bool			_init;
};
#endif

/** The CAST-128 cipher. Published in 1996 and in RFC 2144. OpenSSL
 * implementation. */
class Cipher_cast5 : public Cipher {
public:
	Cipher_cast5() : Cipher(cipher_type::CAST5), _init(false) {}
	~Cipher_cast5() noexcept {}

	void init(const uint8_t *key, size_t sz) noexcept(false) {
		// CAST_set_key() doesn't check its input size (or silently
		// fixes it)
		const std::vector<uint16_t> &sizes =
		    Cipher_traits::traits(cipher_type::CAST5)->key_sizes;
		if (!std::binary_search(sizes.begin(), sizes.end(), sz))
			throw Crypt_error("bad key size");

		_init = true;
		CAST_set_key(&_key, sz, key);
	}

	void encrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no encryption key set");
		CAST_ecb_encrypt(in, out, &_key, CAST_ENCRYPT);
	}

	void decrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no decryption key set");
		CAST_ecb_encrypt(in, out, &_key, CAST_DECRYPT);
	}

private:
	CAST_KEY		_key;
	bool			_init;
};

/** The CAST-256 cipher. Published in 1998 and in RFC 2612. Submitted to AES
 * but not among the finalists. Independent implementation. */
class Cipher_cast6 : public Cipher {
public:
	Cipher_cast6() : Cipher(cipher_type::CAST6), _init(false) {}
	~Cipher_cast6() noexcept {}

	void init(const uint8_t *key, size_t sz) noexcept(false) {
		if (!cast6_init(&_ctx, key, sz))
			throw Crypt_error("bad key size");
		_init = true;
	}

	void encrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no encryption key set");
		cast6_encrypt(&_ctx, in, out);
	}

	void decrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no decryption key set");
		cast6_decrypt(&_ctx, in, out);
	}

private:
	struct cast6_ctx	_ctx;
	bool			_init;
};

/** The Serpent cipher. Published in 1998. Ranked second in the AES
 * competition. Arguably more secure, but slower, than Rijndael. Independent
 * implementation. */
class Cipher_serpent : public Cipher {
public:
	Cipher_serpent() : Cipher(cipher_type::SERPENT), _init(false) {}
	~Cipher_serpent() noexcept {}

	void init(const uint8_t *key, size_t sz) noexcept(false) {
		if (serpent_init(&_ctx, key, sz) == SERPENT_BAD_KEY_MAT)
			throw Crypt_error("bad key size");
		_init = true;
	}

	void encrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no encryption key set");
		serpent_encrypt(&_ctx, in, out);
	}

	void decrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no decryption key set");
		serpent_decrypt(&_ctx, in, out);
	}

private:
	struct serpent_ctx	_ctx;
	bool			_init;
};

/** The Twofish cipher. Published in 1998. Ranked third in the AES
 * competition. Reference implementation. */
class Cipher_twofish : public Cipher {
public:
	Cipher_twofish() : Cipher(cipher_type::TWOFISH), _init(false) {}
	~Cipher_twofish() noexcept {}

	void init(const uint8_t *key, size_t sz) noexcept(false) {
		if (!twofish_init(&_ctx, key, sz))
			throw Crypt_error("bad key size");
		_init = true;
	}

	void encrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no encryption key set");
		twofish_encrypt(&_ctx, in, out);
	}

	void decrypt(const uint8_t *in, uint8_t *out) noexcept(false) {
		if (!_init)
			throw Crypt_error("no decryption key set");
		twofish_decrypt(&_ctx, in, out);
	}

private:
	struct twofish_ctx	_ctx;
	bool			_init;
};


}

#endif
