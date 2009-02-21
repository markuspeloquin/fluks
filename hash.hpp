#ifndef LUKS_HASH_HPP
#define LUKS_HASH_HPP

#include <stdint.h> // no cstdint yet

#include <cstddef>
#include <exception>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <tr1/memory>
#include <boost/scoped_array.hpp>

#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include "luks.hpp"
#include "ssl.hpp"
#include "tiger.hpp"

namespace luks {

struct Hash_error : virtual std::exception {
};

enum hash_type	    hash_type(const std::string &);
std::string	    hash_name(enum hash_type);

/** Get the size of a hash's digest.
 *
 * \param type	    The hash algorithm.
 * \return	    The size of the hash's digest in bytes.
 */
size_t		    hash_size(enum hash_type type);

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
	{	return create(hash_type(name)); }

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
	 * \see length()
	 */
	virtual void end(uint8_t *buf) throw (Hash_error) = 0;

	/** Get the size of the digest.
	 *
	 * \return	The size in bytes.
	 */
	virtual size_t length() const = 0;
};

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
	 * \param key	The HMAC key.
	 * \param sz	The size of <code>key</code> in bytes.
	 */
	virtual void init(const uint8_t *key, size_t sz) throw () = 0;

	/** Pipe data into the HMAC computation.
	 *
	 * \param buf	Bytes to add.
	 * \param sz	Number of bytes in <code>buf</code>.
	 */
	virtual void add(const uint8_t *, size_t) throw () = 0;

	/** End the hashing sequence and return the result.
	 *
	 * \param[out] buf	Output buffer.
	 * \param[in] sz	The size of the output buffer, should be at
	 *	least as large as length().
	 * \see length()
	 * \throw std::length_error	The output buffer was not large
	 *	enough.
	 */
	virtual void end(uint8_t *buf, unsigned sz)
		throw (std::length_error) = 0;

	/** Get the size of the digest.
	 *
	 * \return	The size in bytes.
	 */
	virtual size_t length() const = 0;
};

/** An SSL hashing error. */
struct Ssl_hash_error : Hash_error, Ssl_error {
	Ssl_hash_error() {}
	~Ssl_hash_error() throw() {}
};

// thankfully, all SSL functions have the same interface
template <
    typename CTX,
    int (*Init)(CTX *),
    int (*Update)(CTX *, const void *, size_t),
    int (*Final)(uint8_t *, CTX *),
    size_t SIZE>
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
	size_t length() const
	{	return SIZE; }

private:
	CTX _ctx;
	bool _valid;
};

// users probably shouldn't use this, but it's here more for completeness
typedef Hash_ssl<
    MD5_CTX, MD5_Init, MD5_Update, MD5_Final,
    MD5_DIGEST_LENGTH>
    Hash_md5;

typedef Hash_ssl<
    RIPEMD160_CTX, RIPEMD160_Init, RIPEMD160_Update, RIPEMD160_Final,
    RIPEMD160_DIGEST_LENGTH>
    Hash_rmd160;

// SHA family of hashes
typedef Hash_ssl<
    SHA_CTX, SHA1_Init, SHA1_Update, SHA1_Final,
    SHA_DIGEST_LENGTH>
    Hash_sha1;

typedef Hash_ssl<
    SHA256_CTX, SHA224_Init, SHA224_Update, SHA224_Final,
    SHA224_DIGEST_LENGTH>
    Hash_sha224;

typedef Hash_ssl<
    SHA256_CTX, SHA256_Init, SHA256_Update, SHA256_Final,
    SHA256_DIGEST_LENGTH>
    Hash_sha256;

typedef Hash_ssl<
    SHA512_CTX, SHA384_Init, SHA384_Update, SHA384_Final,
    SHA384_DIGEST_LENGTH>
    Hash_sha384;

typedef Hash_ssl<
    SHA512_CTX, SHA512_Init, SHA512_Update, SHA512_Final,
    SHA512_DIGEST_LENGTH>
    Hash_sha512;

template <size_t BITS>
class Hash_tiger : public Hash_function {
	Hash_tiger(unsigned passes=3) :
		_passes(passes)
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
		if (BITS < 192) {
			// truncate output
			uint8_t buf2[TIGER_SZ_DIGEST];
			tiger_end(&_ctx, buf2);
			std::copy(buf2, buf2 + BITS/8, buf);
		} else
			tiger_end(&_ctx, buf);
	}
	size_t length() const
	{	return BITS/8; }

private:
	tiger_ctx	_ctx;
	unsigned	_passes;
};

typedef Hash_tiger<128> Hash_tiger128;
typedef Hash_tiger<160> Hash_tiger160;
typedef Hash_tiger<192> Hash_tiger192;

template <
    const EVP_MD *(*EVP_hashfn)(),
    size_t SIZE>
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
	void init(const uint8_t *key, size_t sz) throw()
	{
		HMAC_Init_ex(&_ctx, key, sz, _md, 0);
		_valid = true;
	}
	void add(const uint8_t *data, size_t sz) throw()
	{
		if (!_valid) return;
		HMAC_Update(&_ctx, data, sz);
	}
	void end(uint8_t *out, unsigned sz) throw (std::length_error)
	{
		if (!_valid) return;
		if (sz < SIZE)
			throw std::length_error(
			    "HMAC output buffer not large enough");
		HMAC_Final(&_ctx, out, &sz);
		_valid = false;
	}
	size_t length() const
	{	return SIZE; }

private:
	HMAC_CTX	_ctx;
	const EVP_MD	*_md;
	bool		_valid;
};

typedef Hmac_ssl<EVP_md5, MD5_DIGEST_LENGTH>		Hmac_md5;
typedef Hmac_ssl<EVP_ripemd160, RIPEMD160_DIGEST_LENGTH>
							Hmac_rmd160;
typedef Hmac_ssl<EVP_sha1, SHA_DIGEST_LENGTH>		Hmac_sha1;
typedef Hmac_ssl<EVP_sha224, SHA224_DIGEST_LENGTH>	Hmac_sha224;
typedef Hmac_ssl<EVP_sha256, SHA256_DIGEST_LENGTH>	Hmac_sha256;
typedef Hmac_ssl<EVP_sha384, SHA384_DIGEST_LENGTH>	Hmac_sha384;
typedef Hmac_ssl<EVP_sha512, SHA512_DIGEST_LENGTH>	Hmac_sha512;

template <size_t BITS>
class Hmac_tiger : public Hmac_function {
public:
	Hmac_tiger() {}
	~Hmac_tiger() throw () {}

	void init(const uint8_t *key, size_t sz) throw()
	{
	}
	void add(const uint8_t *data, size_t sz) throw()
	{
	}
	void end(uint8_t *out, unsigned sz) throw (std::length_error)
	{
	}
	size_t length() const
	{	return BITS / 8; }

private:
};

typedef Hmac_tiger<128> Hmac_tiger128;
typedef Hmac_tiger<160> Hmac_tiger160;
typedef Hmac_tiger<192> Hmac_tiger192;

}

#endif
