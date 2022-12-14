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

#ifndef FLUKS_HMAC_HPP
#define FLUKS_HMAC_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <openssl/evp.h>

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
	Hmac_function(hash_type type) :
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
	static std::shared_ptr<Hmac_function> create(const std::string &name)
	{	return create(Hash_traits::type(name)); }

	/**
	 * Create an HMAC function, in an abstract sense, given a hash type.
	 *
	 * \param type	The hash algorithm.
	 * \return	An HMAC function pointer.
	 */
	static std::shared_ptr<Hmac_function> create(hash_type type);

	virtual ~Hmac_function() noexcept {}

	/**
	 * Call this to set or reset the HMAC function's context. It must be
	 * called at the start of each HMAC computation (i.e. each sequence of
	 * calls to add()).
	 *
	 * \param key	The HMAC %key.
	 * \param sz	The size of <code>%key</code> in bytes.
	 */
	virtual void init(const uint8_t *key, size_t sz) = 0;

	/** Pipe data into the HMAC computation.
	 *
	 * \param buf	Bytes to add.
	 * \param sz	Number of bytes in <code>buf</code>.
	 */
	virtual void add(const uint8_t *buf, size_t sz) = 0;

	/** End the hashing sequence and return the result.
	 *
	 * \param[out] buf	Output buffer. At least
	 *	<code>traits()->digest_size</code> bytes.
	 */
	virtual void end(uint8_t *buf) = 0;

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
	Hmac_impl(std::shared_ptr<Hash_function> hashfn) :
		Hmac_function(hashfn->traits()),
		_hashfn(hashfn),
		_key(new uint8_t[hashfn->traits()->block_size])
	{}

	~Hmac_impl() noexcept {}

	void init(const uint8_t *key, size_t sz) noexcept;
	void add(const uint8_t *buf, size_t sz) noexcept
	{	_hashfn->add(buf, sz); }
	void end(uint8_t *out) noexcept;

private:
	Hmac_impl(const Hmac_impl &) : Hmac_function(0) {}
	void operator=(const Hmac_impl &) {}

	std::shared_ptr<Hash_function>	_hashfn;
	std::unique_ptr<uint8_t>	_key;
};


/** OpenSSL HMAC function template */
template <
    const EVP_MD *(*EVP_hashfn)(),
    hash_type type>
class Hmac_evp : public Hmac_function {
public:
	Hmac_evp() :
		Hmac_function(type),
		_md(EVP_hashfn()),
		_valid(false)
	{
		_ctx = EVP_MD_CTX_new();
		if (!_ctx)
			throw Ssl_error();
	}

	~Hmac_evp() noexcept {
		EVP_MD_CTX_free(_ctx);
	}

	void init(const uint8_t *key, size_t sz) {
		EVP_PKEY *pkey = EVP_PKEY_new_mac_key(
		    NID_hmac, nullptr, key, sz
		);
		if (!EVP_DigestSignInit(_ctx, nullptr, _md, nullptr, pkey)) {
			EVP_PKEY_free(pkey);
			throw Ssl_error();
		}
		EVP_PKEY_free(pkey);
		_valid = true;
	}

	void add(const uint8_t *data, size_t sz) {
		if (!_valid) return;
		if (!EVP_DigestSignUpdate(_ctx, data, sz))
			throw Ssl_error();
	}

	void end(uint8_t *out) {
		if (!_valid) return;
		size_t sz = traits()->digest_size;
		if (!EVP_DigestSignFinal(_ctx, out, &sz))
			throw Ssl_error();
		_valid = false;
	}

private:
	EVP_MD_CTX	*_ctx;
	const EVP_MD	*_md;
	bool		_valid;
};


using Hmac_md5 = Hmac_evp<EVP_md5, hash_type::MD5>;
using Hmac_rmd160 = Hmac_evp<EVP_ripemd160, hash_type::RMD160>;
using Hmac_sha1 = Hmac_evp<EVP_sha1, hash_type::SHA1>;
using Hmac_sha224 = Hmac_evp<EVP_sha224, hash_type::SHA224>;
using Hmac_sha256 = Hmac_evp<EVP_sha256, hash_type::SHA256>;
using Hmac_sha384 = Hmac_evp<EVP_sha384, hash_type::SHA384>;
using Hmac_sha512 = Hmac_evp<EVP_sha512, hash_type::SHA512>;


}

#endif
