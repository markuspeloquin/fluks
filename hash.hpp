/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
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

#ifndef FLUKS_HASH_HPP
#define FLUKS_HASH_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <streambuf>
#include <string>

#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include "errors.hpp"
#include "luks.hpp"
#include "support.hpp"
#include "tiger.h"
#include "whirlpool.h"

namespace fluks {

/** Information for a hash function */
class Hash_traits {
public:
	/** Required for storage in a vector, otherwise not used */
	Hash_traits() {}

	/** Init the struct
	 * \param name	    The hash name
	 * \param sz_blk    The block size
	 * \param sz_dig    The digest size
	 * \param version   The version of LUKS required, or 0 if not in LUKS
	 */
	Hash_traits(const std::string &name, uint16_t sz_blk, uint16_t sz_dig,
	    uint16_t version) :
		name(name),
		block_size(sz_blk),
		digest_size(sz_dig),
		luks_version(version)
	{}

	/** Get the information for the specified hash function
	 * \param type	The type of the hash function
	 * \return	The properties of the function
	 */
	static const Hash_traits *traits(hash_type type);

	/** Get the type of the named hash function
	 * \param name	The name of the function
	 * \return	The type
	 */
	static hash_type type(const std::string &name);

	/** Get the hash types supported by fluks
	 * \return	The shit
	 */
	static const std::vector<hash_type> &types();

	std::string name; /**< The hash name */
	uint16_t block_size;
	uint16_t digest_size;
	/** The version of LUKS required, or 0 if not in LUKS */
	uint16_t luks_version;
};

/** Computes hash function digests */
class Hash_function {
public:
	Hash_function(hash_type type) :
		_traits(Hash_traits::traits(type))
	{}

	/** Create a hash function given a hash spec.
	 *
	 * \param name	The hash spec.
	 * \return	A hash function pointer, <code>nullptr</code> for
	 *	unrecognized specs.
	 * \see create(type)
	 */
	static std::shared_ptr<Hash_function> create(const std::string &name) {
		return create(Hash_traits::type(name));
	}

	/** Create a hash function given a hash type.
	 *
	 * \param type	The hash algorithm.
	 * \return	A hash function pointer.
	 */
	static std::shared_ptr<Hash_function> create(hash_type type);

	virtual ~Hash_function() noexcept {}

	/**
	 * Call this to set or reset the hashing function's context. It must
	 * be called at the start of each hash computation (i.e. each
	 * sequence of calls to add()).
	 *
	 * \throw Hash_error	The hashing function has some error. This
	 *	shouldn't happen.
	 */
	virtual void init() = 0;

	/** Pipe data into the hash computation.
	 *
	 * \param buf	Bytes to add.
	 * \param sz	Number of bytes in <code>buf</code>.
	 *
	 * \throw Hash_error	The hashing function has some error. This
	 *	shouldn't happen.
	 */
	virtual void add(const uint8_t *buf, size_t sz) = 0;

	/** End the hashing sequence and return the result.
	 *
	 * \param[out] buf	Output buffer, assumed to be large enough.
	 * \see digest_size()
	 */
	virtual void end(uint8_t *buf) = 0;

	/** Get information on the hash function
	 *
	 * \return	properties of the function
	 */
	const Hash_traits *traits() const {
		return _traits;
	}

private:
	const Hash_traits *_traits;
};


/** OpenSSL hash function template */
template <
    typename CTX,
    int (*Init)(CTX *),
    int (*Update)(CTX *, const void *, size_t),
    int (*Final)(uint8_t *, CTX *),
    hash_type type>
class Hash_ssl : public Hash_function {
public:
	Hash_ssl() : Hash_function(type), _valid(false) {}
	~Hash_ssl() noexcept {}

	void init() {
		_valid = false;
		if (!Init(&_ctx)) throw Ssl_hash_error();
		_valid = true;
	}

	void add(const uint8_t *buf, size_t sz) {
		if (!_valid) return;
		if (!Update(&_ctx, buf, sz)) throw Ssl_hash_error();
	}

	void end(uint8_t *buf) {
		if (!_valid) return;
		if (!Final(buf, &_ctx)) throw Ssl_hash_error();
		_valid = false;
	}

private:
	CTX _ctx;
	bool _valid;
};


/** Tiger hash function */
class Hash_tiger : public Hash_function {
public:
	/** Create a Tiger hash object
	 *
	 * \param type		The type of the Tiger hash, must be one of
	 *	{ TIGER128, TIGER160, TIGER192 }.
	 * \param version	The Tiger padding version to use. Note that
	 *	the Linux kernel uses version 1, so that's probably more
	 *	appropriate.
	 */
	Hash_tiger(hash_type type, uint8_t version=1) :
		Hash_function(type),
		_version(version),
		_valid(false)
	{
		Assert(
		    type == hash_type::TIGER128 ||
		    type == hash_type::TIGER160 ||
		    type == hash_type::TIGER192,
		    "Hash_tiger constructor needs a TIGER* enum value");
	}

	~Hash_tiger() noexcept {}

	void init() noexcept {
		tiger_init(&_ctx, _version);
		_valid = true;
	}

	void add(const uint8_t *buf, size_t sz) noexcept {
		if (!_valid) return;
		tiger_update(&_ctx, buf, sz);
	}

	void end(uint8_t *buf) noexcept {
		if (!_valid) return;
		tiger_end(&_ctx, buf, traits()->digest_size);
		_valid = false;
	}

private:
	tiger_ctx	_ctx;
	uint8_t		_version;
	bool		_valid;
};


/** Whirlpool hash function */
class Hash_whirlpool : public Hash_function {
public:
	/** Create a Whirlpool hash object
	 *
	 * \param type the type of the Whirlpool hash, must be one of
	 *	of { WHIRLPOOL256, WHIRLPOOL384, WHIRLPOOL512 }.
	 */
	Hash_whirlpool(hash_type type) :
		Hash_function(type),
		_valid(false)
	{
		Assert(
		    type == hash_type::WHIRLPOOL256 ||
		    type == hash_type::WHIRLPOOL384 ||
		    type == hash_type::WHIRLPOOL512,
		    "Hash_whirlpool constructor needs a WHIRLPOOL* enum value");
	}

	~Hash_whirlpool() noexcept {}

	void init() noexcept {
		whirlpool_init(&_ctx);
		_valid = true;
	}

	void add(const uint8_t *buf, size_t sz) noexcept {
		if (!_valid) return;
		whirlpool_update(&_ctx, buf, sz);
	}

	void end(uint8_t *buf) noexcept {
		if (!_valid) return;
		whirlpool_end(&_ctx, buf, traits()->digest_size);
	}

private:
	whirlpool_ctx	_ctx;
	bool		_valid;
};

using Hash_md5 = Hash_ssl<MD5_CTX,
    MD5_Init, MD5_Update, MD5_Final,
    hash_type::MD5>;
using Hash_rmd160 = Hash_ssl<RIPEMD160_CTX,
    RIPEMD160_Init, RIPEMD160_Update, RIPEMD160_Final,
    hash_type::RMD160>;
using Hash_sha1 = Hash_ssl<SHA_CTX,
    SHA1_Init, SHA1_Update, SHA1_Final,
    hash_type::SHA1>;
using Hash_sha224 = Hash_ssl<SHA256_CTX,
    SHA224_Init, SHA224_Update, SHA224_Final,
    hash_type::SHA224>;
using Hash_sha256 = Hash_ssl<SHA256_CTX,
    SHA256_Init, SHA256_Update, SHA256_Final,
    hash_type::SHA256>;
using Hash_sha384 = Hash_ssl<SHA512_CTX,
    SHA384_Init, SHA384_Update, SHA384_Final,
    hash_type::SHA384>;
using Hash_sha512 = Hash_ssl<SHA512_CTX,
    SHA512_Init, SHA512_Update, SHA512_Final,
    hash_type::SHA512>;

}

#endif
