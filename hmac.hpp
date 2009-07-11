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

#ifndef FLUKS_HMAC_HPP
#define FLUKS_HMAC_HPP

#include <cstddef>
#include <string>
#include <tr1/cstdint>
#include <tr1/memory>
#include <boost/scoped_array.hpp>

#include <openssl/hmac.h>

#include "hash.hpp"
#include "luks.hpp"
#include "support.hpp"

namespace fluks {

/** Computes hash function digests using HMAC */
struct Hmac_function {
protected:
	/** Init the hash properties
	 * \param type The hash type
	 */
	Hmac_function(enum hash_type type) :
		_traits(Hash_traits::traits(type))
	{}
	/** Init the hash properties
	 * \param traits The hash information
	 */
	Hmac_function(const Hash_traits *traits) : _traits(traits) {}

public:
	/**
	 * Create an HMAC function, in an abstract sense, given a hash spec.
	 *
	 * \param name	The hash spec.
	 * \return	An HMAC function pointer, <code>nullptr</code> for
	 *	unrecognized specs.
	 * \see create(type)
	 */
	static std::tr1::shared_ptr<Hmac_function>
	    create(const std::string &name)
	{	return create(Hash_traits::type(name)); }

	/**
	 * Create an HMAC function, in an abstract sense, given a hash type.
	 *
	 * \param type	The hash algorithm.
	 * \return	An HMAC function pointer.
	 */
	static std::tr1::shared_ptr<Hmac_function>
	    create(enum hash_type type);

	virtual ~Hmac_function() throw () {}

	/**
	 * Call this to set or reset the HMAC function's context.  It must
	 * be called at the start of each HMAC computation (i.e. each
	 * sequence of calls to add()).
	 *
	 * \param key	The HMAC %key.
	 * \param sz	The size of <code>%key</code> in bytes.
	 */
	virtual void init(const uint8_t *key, size_t sz) throw () = 0;

	/** Pipe data into the HMAC computation.
	 *
	 * \param buf	Bytes to add.
	 * \param sz	Number of bytes in <code>buf</code>.
	 */
	virtual void add(const uint8_t *buf, size_t sz) throw () = 0;

	/** End the hashing sequence and return the result.
	 *
	 * \param[out] buf	Output buffer. At least
	 *	<code>traits()->digest_size</code> bytes.
	 */
	virtual void end(uint8_t *buf) throw () = 0;

	/** Get the traits of the underlying hash function.
	 *
	 * \return	The hash function properties
	 */
	const Hash_traits *traits() const
	{	return _traits; }

private:
	const Hash_traits *_traits;
};


/** An HMAC function implemented in terms of a Hash_function object */
class Hmac_impl : public Hmac_function {
public:
	static const uint8_t IPAD = 0x36;
	static const uint8_t OPAD = 0x5c;

	/** Create an HMAC object tied to a particular hash function
	 *
	 * \param hashfn	A hash object.
	 */
	Hmac_impl(std::tr1::shared_ptr<Hash_function> hashfn) :
		Hmac_function(hashfn->traits()),
		_hashfn(hashfn),
		_key(new uint8_t[hashfn->traits()->block_size])
	{}

	~Hmac_impl() throw () {}

	void init(const uint8_t *key, size_t sz) throw ();
	void add(const uint8_t *buf, size_t sz) throw ()
	{	_hashfn->add(buf, sz); }
	void end(uint8_t *out) throw ();

private:
	Hmac_impl(const Hmac_impl &h) : Hmac_function(0) {}
	void operator=(const Hmac_impl &h) {}

	std::tr1::shared_ptr<Hash_function> _hashfn;
	boost::scoped_array<uint8_t> _key;
};


/** OpenSSL HMAC function template */
template <
    const EVP_MD *(*EVP_hashfn)(),
    enum hash_type type>
class Hmac_ssl : public Hmac_function {
public:
	Hmac_ssl() :
		Hmac_function(type),
		_md(EVP_hashfn()),
		_valid(false)
	{
		HMAC_CTX_init(&_ctx);
	}
	~Hmac_ssl() throw ()
	{	HMAC_CTX_cleanup(&_ctx); }
	void init(const uint8_t *key, size_t sz) throw ()
	{
		HMAC_Init_ex(&_ctx, key, sz, _md, 0);
		_valid = true;
	}
	void add(const uint8_t *data, size_t sz) throw ()
	{
		if (!_valid) return;
		HMAC_Update(&_ctx, data, sz);
	}
	void end(uint8_t *out) throw ()
	{
		if (!_valid) return;
		unsigned sz = traits()->digest_size;
		HMAC_Final(&_ctx, out, &sz);
		_valid = false;
	}

private:
	HMAC_CTX	_ctx;
	const EVP_MD	*_md;
	bool		_valid;
};


typedef Hmac_ssl<EVP_md5, HT_MD5>		Hmac_md5;
typedef Hmac_ssl<EVP_ripemd160, HT_RMD160>	Hmac_rmd160;
typedef Hmac_ssl<EVP_sha1, HT_SHA1>		Hmac_sha1;
typedef Hmac_ssl<EVP_sha224, HT_SHA224>		Hmac_sha224;
typedef Hmac_ssl<EVP_sha256, HT_SHA256>		Hmac_sha256;
typedef Hmac_ssl<EVP_sha384, HT_SHA384>		Hmac_sha384;
typedef Hmac_ssl<EVP_sha512, HT_SHA512>		Hmac_sha512;


}

#endif
