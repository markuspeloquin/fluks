#ifndef HMAC_HPP
#define HMAC_HPP

#include <stdint.h>

#include <cstddef>
#include <string>
#include <tr1/memory>
#include <boost/scoped_array.hpp>

#include "hash.hpp"
#include "luks.hpp"

namespace luks {

struct Hmac_function {

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
	{	return create(hash_type(name)); }

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
	virtual void init(const uint8_t *key, size_t sz)
		throw (std::length_error) = 0;

	/** Pipe data into the HMAC computation.
	 *
	 * \param buf	Bytes to add.
	 * \param sz	Number of bytes in <code>buf</code>.
	 */
	virtual void add(const uint8_t *buf, size_t sz) throw () = 0;

	/** End the hashing sequence and return the result.
	 *
	 * \param[out] buf	Output buffer.
	 * \see length()
	 */
	virtual void end(uint8_t *buf) throw () = 0;

	/** Get the size of the digest.
	 *
	 * \return	The size in bytes.
	 */
	virtual size_t length() const = 0;

	/** The size of the blocks.
	 *
	 * \return	The size in bytes.
	 */
	virtual size_t blocksize() const = 0;
};


/** An HMAC function implemented in terms of a Hash_function object */
class Hmac_impl : public Hmac_function {
public:
	/** Create an HMAC object tied to a particular hash function
	 *
	 * \param hashfn	A hash object.
	 */
	Hmac_impl(std::tr1::shared_ptr<Hash_function> hashfn) :
		_hashfn(hashfn),
		_ipad(new uint8_t[hashfn->blocksize()]),
		_key(new uint8_t[hashfn->blocksize()]),
		_opad(new uint8_t[hashfn->blocksize()])
	{
		std::fill(_ipad.get(), _ipad.get() + blocksize(), 0x36);
		std::fill(_ipad.get(), _ipad.get() + blocksize(), 0x5c);
	}

	~Hmac_impl() throw () {}

	void init(const uint8_t *key, size_t sz) throw (std::length_error);
	void add(const uint8_t *buf, size_t sz) throw ()
	{	_hashfn->add(buf, sz); }
	void end(uint8_t *out) throw();
	size_t length() const
	{	return _hashfn->length(); }
	size_t blocksize() const
	{	return _hashfn->blocksize(); }

private:
	Hmac_impl(const Hmac_impl &h) {}
	void operator=(const Hmac_impl &h) {}

	std::tr1::shared_ptr<Hash_function> _hashfn;
	boost::scoped_array<uint8_t> _ipad;
	boost::scoped_array<uint8_t> _key;
	boost::scoped_array<uint8_t> _opad;
};


/** OpenSSL HMAC function template */
template <
    const EVP_MD *(*EVP_hashfn)(),
    size_t SIZE,
    size_t BLOCKSIZE>
class Hmac_ssl : public Hmac_function {
public:
	Hmac_ssl() :
		_md(EVP_hashfn()),
		_valid(false)
	{
		HMAC_CTX_init(&_ctx);
	}
	~Hmac_ssl() throw ()
	{
		HMAC_CTX_cleanup(&_ctx);
	}
	void init(const uint8_t *key, size_t sz) throw (std::length_error)
	{
		if (sz > BLOCKSIZE)
			throw std::length_error(
			    "HMAC key length cannot exceed the block size "
			    "of the hash");
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
		unsigned sz = length();
		HMAC_Final(&_ctx, out, &sz);
		_valid = false;
	}
	size_t length() const
	{	return SIZE; }
	size_t blocksize() const
	{	return BLOCKSIZE; }

private:
	HMAC_CTX	_ctx;
	const EVP_MD	*_md;
	bool		_valid;
};


typedef Hmac_ssl<EVP_md5, MD5_DIGEST_LENGTH, MD5_CBLOCK>
    Hmac_md5;
typedef Hmac_ssl<EVP_ripemd160, RIPEMD160_DIGEST_LENGTH, RIPEMD160_CBLOCK>
    Hmac_rmd160;
typedef Hmac_ssl<EVP_sha1, SHA_DIGEST_LENGTH, SHA_CBLOCK>
    Hmac_sha1;
typedef Hmac_ssl<EVP_sha224, SHA224_DIGEST_LENGTH, SHA256_CBLOCK>
    Hmac_sha224;
typedef Hmac_ssl<EVP_sha256, SHA256_DIGEST_LENGTH, SHA256_CBLOCK>
    Hmac_sha256;
typedef Hmac_ssl<EVP_sha384, SHA384_DIGEST_LENGTH, SHA512_CBLOCK>
    Hmac_sha384;
typedef Hmac_ssl<EVP_sha512, SHA512_DIGEST_LENGTH, SHA512_CBLOCK>
    Hmac_sha512;


}

#endif
