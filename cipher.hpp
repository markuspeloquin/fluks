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

#include <openssl/evp.h>
#include <openssl/opensslconf.h>

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
	virtual void init(const uint8_t *key, size_t sz_key) = 0;

	/** Encrypt a block of data
	 *
	 * \param in	Plaintext
	 * \param out	Ciphertext, usually cannot be equal to <code>in</code>.
	 * \throw Crypt_error	This will occur if the init() function was
	 *	not first called or if <code>in<code> cannot be equal to
	 *	</code>out</code>.
	 */
	virtual void encrypt(const uint8_t *in, uint8_t *out) = 0;

	/** Decrypt a block of data
	 *
	 * \param in	Ciphertext
	 * \param out	Plaintext, usually cannot be equal to <code>in</code>.
	 * \throw Crypt_error	This will occur if the init() function was
	 *	not first called or if <code>in<code> cannot be equal to
	 *	</code>out</code>.
	 */
	virtual void decrypt(const uint8_t *in, uint8_t *out) = 0;

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

/** Generic OpenSSL implementation. */
template<
    int cipher_nid,
    cipher_type type,
    int cipher_nid_192 = -1,
    int cipher_nid_256 = -1
>
class Cipher_evp : public Cipher {
public:
	Cipher_evp() : Cipher(type), _init(false) {}

	~Cipher_evp() noexcept {
		if (_ctx)
			EVP_CIPHER_CTX_free(_ctx);
	}

	Cipher_evp(const Cipher_evp &) = delete;
	void operator=(const Cipher_evp &) = delete;

	void init(const uint8_t *key, size_t sz) {
		int nid = cipher_nid_192 > 0 && sz == 192/8 ? cipher_nid_192 :
		    cipher_nid_256 > 0 && sz == 256/8 ? cipher_nid_256 :
		    cipher_nid;

		if (_ctx) {
			if (!EVP_CIPHER_CTX_reset(_ctx))
				throw Ssl_error();
		} else {
			if (!(_ctx = EVP_CIPHER_CTX_new()))
				throw Ssl_error();
		}

		_cipher = nullptr;
		_key_data.reset(nullptr);

		const EVP_CIPHER *cipher = EVP_get_cipherbynid(nid);
		if (cipher == nullptr)
			throw Ssl_error();
		_cipher = cipher;

		_key_data.reset(new uint8_t[sz]);
		std::copy(key, key + sz, _key_data.get());
		_sz = sz;
		_dir = crypt_direction::NONE;
		_init = true;
	}

	void encrypt(const uint8_t *in, uint8_t *out) {
		if (!_init)
			throw Crypt_error("no en/decryption key set");
		if (_dir != crypt_direction::ENCRYPT) {
			if (EVP_EncryptInit_ex(
			      _ctx, _cipher, nullptr, _key_data.get(), nullptr
			)) {
				throw Ssl_error();
			}
			_dir = crypt_direction::ENCRYPT;
		}
		int inl = traits()->block_size;
		int outl = 0;
		if (!EVP_EncryptUpdate(_ctx, out, &outl, in, inl))
			throw Ssl_error();
		else if (outl != inl)
			throw Crypt_error("ciphertext length is wrong");
	}

	void decrypt(const uint8_t *in, uint8_t *out) {
		if (!_init)
			throw Crypt_error("no en/decryption key set");
		if (_dir != crypt_direction::DECRYPT) {
			if (EVP_DecryptInit_ex(
			      _ctx, _cipher, nullptr, _key_data.get(), nullptr
			)) {
				throw Ssl_error();
			}
		}
		int inl = traits()->block_size;
		int outl = 0;
		if (!EVP_DecryptUpdate(_ctx, out, &outl, in, inl))
			throw Ssl_error();
		else if (outl != inl)
			throw Crypt_error("plaintext length is wrong");
	}

private:
	const EVP_CIPHER	*_cipher;
	EVP_CIPHER_CTX		*_ctx;
	std::unique_ptr<uint8_t> _key_data;
	size_t			_sz;
	crypt_direction		_dir;
	bool			_init;
};


/** The Rijndael cipher. Published in 1998. AES winner, with CRYPTREC, NESSIE,
 * NSA certifications. OpenSSL implementation. */
using Cipher_aes = Cipher_evp<
    NID_aes_128_ecb, cipher_type::AES, NID_aes_192_ecb, NID_aes_256_ecb
>;


/** The Blowfish cipher. Published in 1993. OpenSSL implementation. */
using Cipher_blowfish = Cipher_evp<NID_bf_ecb, cipher_type::BLOWFISH>;


/** The Camellia cipher. Published in 2000. CRYPTREC, NESSIE certification.
 * OpenSSL implementation. */
using Cipher_camellia = Cipher_evp<
    NID_camellia_128_ecb,
    cipher_type::CAMELLIA,
    NID_camellia_192_ecb,
    NID_camellia_256_ecb
>;


/** The CAST-128 cipher. Published in 1996 and in RFC 2144. OpenSSL
 * implementation. */
using Cipher_cast5 = Cipher_evp<NID_cast5_ecb, cipher_type::CAST5>;


/** The CAST-256 cipher. Published in 1998 and in RFC 2612. Submitted to AES
 * but not among the finalists. Independent implementation. */
class Cipher_cast6 : public Cipher {
public:
	Cipher_cast6() : Cipher(cipher_type::CAST6), _init(false) {}
	~Cipher_cast6() noexcept {}

	void init(const uint8_t *key, size_t sz) {
		if (!cast6_init(&_ctx, key, sz))
			throw Crypt_error("bad key size");
		_init = true;
	}

	void encrypt(const uint8_t *in, uint8_t *out) {
		if (!_init)
			throw Crypt_error("no encryption key set");
		cast6_encrypt(&_ctx, in, out);
	}

	void decrypt(const uint8_t *in, uint8_t *out) {
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

	void init(const uint8_t *key, size_t sz) {
		if (serpent_init(&_ctx, key, sz) == SERPENT_BAD_KEY_MAT)
			throw Crypt_error("bad key size");
		_init = true;
	}

	void encrypt(const uint8_t *in, uint8_t *out) {
		if (!_init)
			throw Crypt_error("no encryption key set");
		serpent_encrypt(&_ctx, in, out);
	}

	void decrypt(const uint8_t *in, uint8_t *out) {
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

	void init(const uint8_t *key, size_t sz) {
		if (!twofish_init(&_ctx, key, sz))
			throw Crypt_error("bad key size");
		_init = true;
	}

	void encrypt(const uint8_t *in, uint8_t *out) {
		if (!_init)
			throw Crypt_error("no encryption key set");
		twofish_encrypt(&_ctx, in, out);
	}

	void decrypt(const uint8_t *in, uint8_t *out) {
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
