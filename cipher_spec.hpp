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

#ifndef CIPHER_SPEC_HPP
#define CIPHER_SPEC_HPP

#include <string>

#include "errors.hpp"

namespace fluks {

/** Ciphers supported by <em>fluks</em> */
enum class cipher_type {
	UNDEFINED = 0,
	AES,
	BLOWFISH,
#ifndef OPENSSL_NO_CAMELLIA
	CAMELLIA,
#endif
	CAST5,
	CAST6,
	TWOFISH,
	SERPENT
};

/** Cipher block modes supported by <em>fluks</em> */
enum class block_mode {
	UNDEFINED = 0,
	CBC, /**< Cipher-block chaining */
	CBC_CTS, /**< Cipher-block chaining with ciphertext stealing */
	CFB, /**< Cipher feedback */
	CTR, /**< Counter */
	/** Cipher Text Stealing
	 *
	 * Described in RFC 2040, Section 8 */
	ECB, /**< Electronic codebook */
	OFB, /**< Output feedback */
	PCBC /**< Propogating cipher-block chaining */
};

enum class iv_mode {
	UNDEFINED = 0,
	PLAIN,
	ESSIV
};

/** Hash types supported by <em>fluks</em>
 *
 * Tiger is optimized for 64-bit architectures, designed by the same folks
 * who brought you the Serpent cipher. Tiger/{128,160} are just truncated
 * versions of Tiger/192.
 *
 * Along with SHA-{1,256,384,512} and RMD-{128,160}, WHIRLPOOL is included
 * in ISO/IEC's list of recommended hash functions (10118-3), and is
 * also recommended by NESSIE. WHIRLPOOL-{256,384} are just truncated
 * versions.
 */
enum class hash_type {
	UNDEFINED = 0,
	MD5,	/**< (you probably should not use this) */
	RMD160,	/**< Possibly better knows as RIPEMD-160 */
	SHA1,
	SHA224,
	SHA256,
	SHA384,
	SHA512,
	TIGER128,
	TIGER160,
	TIGER192,
	WHIRLPOOL256,
	WHIRLPOOL384,
	WHIRLPOOL512
};

class Cipher_traits;
class Hash_traits;

class Cipher_spec {
public:
	Cipher_spec(ssize_t sz_key, const std::string &spec) noexcept(false) {
		reset(sz_key, spec);
	}

	Cipher_spec(ssize_t sz_key, cipher_type cipher,
	    block_mode block_mode=block_mode::UNDEFINED,
	    iv_mode iv_mode=iv_mode::UNDEFINED,
	    hash_type iv_hash=hash_type::UNDEFINED) noexcept(false) {
		reset(sz_key, cipher, block_mode, iv_mode, iv_hash);
	}

	void reset(ssize_t sz_key, const std::string &spec) noexcept(false);
	void reset(ssize_t sz_key, cipher_type cipher,
	    block_mode block_mode=block_mode::UNDEFINED,
	    iv_mode iv_mode=iv_mode::UNDEFINED,
	    hash_type iv_hash=hash_type::UNDEFINED) noexcept(false);

	cipher_type type_cipher() const {
		return _ty_cipher;
	}

	block_mode type_block_mode() const {
		return _ty_block_mode;
	}

	iv_mode type_iv_mode() const {
		return _ty_iv_mode;
	}

	hash_type type_iv_hash() const {
		return _ty_iv_hash;
	}

	const std::string &name_cipher() const {
		return _nm_cipher;
	}

	const std::string &name_block_mode() const {
		return _nm_block_mode;
	}

	const std::string &name_iv_mode() const {
		return _nm_iv_mode;
	}

	const std::string &name_iv_hash() const {
		return _nm_iv_hash;
	}


	std::string canon_cipher() const;
	std::string canon_mode() const;

private:
	void check_spec_support(const Cipher_traits *cipher_traits,
	    const Hash_traits *hash_traits) noexcept(false);
	void check_spec(ssize_t sz_key) noexcept(false);

	std::string	_nm_cipher;
	std::string	_nm_block_mode;
	std::string	_nm_iv_mode;
	std::string	_nm_iv_hash;
	cipher_type	_ty_cipher;
	block_mode	_ty_block_mode;
	iv_mode		_ty_iv_mode;
	hash_type	_ty_iv_hash;
};

}

#endif
