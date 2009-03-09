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

#ifndef FLUKS_HASH_HPP
#define FLUKS_HASH_HPP

#include <stdint.h> // no cstdint yet

#include <cstddef>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <tr1/memory>
#include <boost/scoped_array.hpp>

//#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include "errors.hpp"
#include "luks.hpp"
#include "support.hpp"
#include "tiger.hpp"
#include "whirlpool.h"

namespace fluks {

struct Hash_function {

	/**
	 * Create a hash function, in an abstract sense, given a hash spec.
	 *
	 * \param name	The hash spec.
	 * \return	A hash function pointer, <code>nullptr</code> for
	 *	unrecognized specs.
	 * \see create(type)
	 */
	static std::tr1::shared_ptr<Hash_function>
	create(const std::string &name)
	{	return create(hash_info::type(name)); }

	/**
	 * Create a hash function, in an abstract sense, given a hash type.
	 *
	 * \param type	The hash algorithm.
	 * \return	A hash function pointer.
	 */
	static std::tr1::shared_ptr<Hash_function>
	create(enum hash_type type);

	virtual ~Hash_function() throw () {}

	/**
	 * Call this to set or reset the hashing function's context.  It must
	 * be called at the start of each hash computation (i.e. each
	 * sequence of calls to add()).
	 *
	 * \throw Hash_error	The hashing function has some error.  This
	 *	shouldn't happen.
	 */
	virtual void init() throw (Hash_error) = 0;

	/** Pipe data into the hash computation.
	 *
	 * \param buf	Bytes to add.
	 * \param sz	Number of bytes in <code>buf</code>.
	 *
	 * \throw Hash_error	The hashing function has some error.  This
	 *	shouldn't happen.
	 */
	virtual void add(const uint8_t *buf, size_t sz) throw (Hash_error) = 0;

	/** End the hashing sequence and return the result.
	 *
	 * \param[out] buf	Output buffer, assumed to be large enough.
	 * \see digest_size()
	 */
	virtual void end(uint8_t *buf) throw (Hash_error) = 0;

	/** The size of the digest.
	 *
	 * \return	The size in bytes.
	 */
	virtual size_t digest_size() const = 0;

	/** The size of the blocks.
	 *
	 * \return	The size in bytes.
	 */
	virtual size_t block_size() const = 0;
};


/** OpenSSL hash function template */
template <
    typename CTX,
    int (*Init)(CTX *),
    int (*Update)(CTX *, const void *, size_t),
    int (*Final)(uint8_t *, CTX *),
    size_t SIZE,
    size_t BLOCKSIZE>
class Hash_ssl : public Hash_function {
public:
	Hash_ssl() : _valid(false) {}
	~Hash_ssl() throw () {}

	void init() throw (Hash_error)
	{
		_valid = false;
		if (!Init(&_ctx)) throw Ssl_hash_error();
		_valid = true;
	}
	void add(const uint8_t *buf, size_t sz) throw (Hash_error)
	{
		if (!_valid) return;
		if (!Update(&_ctx, buf, sz)) throw Ssl_hash_error();
	}
	void end(uint8_t *buf) throw (Hash_error)
	{
		if (!_valid) return;
		if (!Final(buf, &_ctx)) throw Ssl_hash_error();
		_valid = false;
	}
	size_t digest_size() const
	{	return SIZE; }
	size_t block_size() const
	{	return BLOCKSIZE; }

private:
	CTX _ctx;
	bool _valid;
};


/** Tiger hash function */
class Hash_tiger : public Hash_function {
public:
	/** Create a Tiger hash object
	 *
	 * \param sz_digest	The size of the digest in bytes.  Must be one
	 *	of { \link TIGER128_SZ_DIGEST\endlink,
	 *	\link TIGER160_SZ_DIGEST\endlink,
	 *	\link TIGER_SZ_DIGEST\endlink }.
	 * \param passes	The number of passes to take in the Tiger
	 *	compression function.  Minumum value is 3.
	 */
	Hash_tiger(size_t sz_digest, unsigned passes=3) :
		_passes(passes < 3 ? 3 : passes),
		_sz(sz_digest)
	{}
	~Hash_tiger() throw () {}

	void init() throw ()
	{
		tiger_init(&_ctx, _passes);
	}
	void add(const uint8_t *buf, size_t sz) throw ()
	{
		tiger_update(&_ctx, buf, sz);
	}
	void end(uint8_t *buf) throw ()
	{
		if (_sz < TIGER_SZ_DIGEST) {
			// truncate output
			uint8_t buf2[TIGER_SZ_DIGEST];
			tiger_end(&_ctx, buf2);
			std::copy(buf2, buf2 + _sz, buf);
		} else
			tiger_end(&_ctx, buf);
	}
	size_t digest_size() const
	{	return _sz; }
	size_t block_size() const
	{	return TIGER_SZ_BLOCK; }

private:
	tiger_ctx	_ctx;
	unsigned	_passes;
	size_t		_sz;
};


/** Whirlpool hash function */
class Hash_whirlpool : public Hash_function {
public:
	/** Create a Whirlpool hash object
	 *
	 * \param sz_digest	The size of the digest in bytes.  Must be one
	 *	of { \link TIGER128_SZ_DIGEST\endlink,
	 *	\link TIGER160_SZ_DIGEST\endlink,
	 *	\link TIGER_SZ_DIGEST\endlink }.
	 * \param passes	The number of passes to take in the Tiger
	 *	compression function.  Minumum value is 3.
	 */
	Hash_whirlpool(size_t sz_digest) :
		_sz(sz_digest)
	{}
	~Hash_whirlpool() throw () {}

	void init() throw ()
	{
		whirlpool_init(&_ctx);
	}
	void add(const uint8_t *buf, size_t sz) throw ()
	{
		whirlpool_update(&_ctx, buf, sz);
	}
	void end(uint8_t *buf) throw ()
	{
		if (_sz < WHIRLPOOL_SZ_DIGEST) {
			// truncate output
			uint8_t buf2[WHIRLPOOL_SZ_DIGEST];
			whirlpool_end(&_ctx, buf2);
			std::copy(buf2, buf2 + _sz, buf);
		} else
			whirlpool_end(&_ctx, buf);
	}
	size_t digest_size() const
	{	return _sz; }
	size_t block_size() const
	{	return WHIRLPOOL_SZ_BLOCK; }

private:
	whirlpool_ctx	_ctx;
	unsigned	_passes;
	size_t		_sz;
};


typedef Hash_ssl<
    MD5_CTX, MD5_Init, MD5_Update, MD5_Final,
    MD5_DIGEST_LENGTH, MD5_CBLOCK>
    Hash_md5;
typedef Hash_ssl<
    RIPEMD160_CTX, RIPEMD160_Init, RIPEMD160_Update, RIPEMD160_Final,
    RIPEMD160_DIGEST_LENGTH, RIPEMD160_CBLOCK>
    Hash_rmd160;
typedef Hash_ssl<
    SHA_CTX, SHA1_Init, SHA1_Update, SHA1_Final,
    SHA_DIGEST_LENGTH, SHA_CBLOCK>
    Hash_sha1;
typedef Hash_ssl<
    SHA256_CTX, SHA224_Init, SHA224_Update, SHA224_Final,
    SHA224_DIGEST_LENGTH, SHA256_CBLOCK>
    Hash_sha224;
typedef Hash_ssl<
    SHA256_CTX, SHA256_Init, SHA256_Update, SHA256_Final,
    SHA256_DIGEST_LENGTH, SHA256_CBLOCK>
    Hash_sha256;
typedef Hash_ssl<
    SHA512_CTX, SHA384_Init, SHA384_Update, SHA384_Final,
    SHA384_DIGEST_LENGTH, SHA512_CBLOCK>
    Hash_sha384;
typedef Hash_ssl<
    SHA512_CTX, SHA512_Init, SHA512_Update, SHA512_Final,
    SHA512_DIGEST_LENGTH, SHA512_CBLOCK>
    Hash_sha512;

}

#endif
