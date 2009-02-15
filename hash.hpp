#ifndef LUKS_HASH_HPP
#define LUKS_HASH_HPP

#include <stdint.h> // no cstdint yet

#include <cstddef>
#include <exception>
#include <stdexcept>
#include <string>
#include <tr1/memory>

#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include "luks.hpp"
#include "ssl.hpp"

namespace luks {

struct Hash_error : std::exception {
};

enum hash_type	    hash_type(const std::string &);
std::string	    hash_name(enum hash_type);
size_t		    hash_size(enum hash_type);

struct Hash_function {

	static std::tr1::shared_ptr<Hash_function>
	create(const std::string &name)
	{	return create(hash_type(name)); }

	static std::tr1::shared_ptr<Hash_function>
	create(enum hash_type type);

	virtual ~Hash_function() throw () {}
	virtual void init() throw (Hash_error) = 0;
	virtual void add(const uint8_t *, size_t) throw (Hash_error) = 0;
	virtual void end(uint8_t *) throw (Hash_error) = 0;
	virtual size_t length() const = 0;
};

struct Hmac_function {

	static std::tr1::shared_ptr<Hmac_function>
	create(const std::string &name)
	{	return create(hash_type(name)); }

	static std::tr1::shared_ptr<Hmac_function>
	create(enum hash_type type);

	virtual ~Hmac_function() throw () {}
	virtual void init(const uint8_t *, size_t) throw () = 0;
	virtual void add(const uint8_t *, size_t) throw () = 0;
	virtual void end(uint8_t *, unsigned) throw (std::length_error) = 0;
	virtual size_t length() const = 0;
};

struct SSL_hash_error : Hash_error {
	SSL_hash_error()
	{
		// for size, see ERR_error_string(3)
		char ssl_err_buf[120];
		ssl_load_errors();
		_msg = "OpenSSL error: ";
		_msg += ERR_error_string(ERR_get_error(), ssl_err_buf);
	}

	~SSL_hash_error() throw() {}

	const char *what() throw()
	{	return _msg.c_str(); }

	std::string _msg;
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
		if (!Init(&_ctx)) throw SSL_hash_error();
		_valid = true;
	}
	void add(const uint8_t *buf, size_t sz) throw (Hash_error)
	{
		if (!_valid) return;
		if (!Update(&_ctx, buf, sz)) throw SSL_hash_error();
	}
	void end(uint8_t *buf) throw (Hash_error)
	{
		if (!_valid) return;
		if (!Final(buf, &_ctx)) throw SSL_hash_error();
		_valid = false;
	}
	size_t length() const
	{	return SIZE; }

private:
	CTX _ctx;
	bool _valid;
};

template <
    const EVP_MD *(*EVP_hashfn)(),
    size_t SIZE>
class Hash_ssl_hmac : public Hash_function {
public:
	Hash_ssl_hmac() : _valid(false)
	{
		HMAC_CTX_init(&_ctx);
		_evp = EVP_hashfn();
	}

	~Hash_ssl_hmac() throw ()
	{
		HMAC_CTX_cleanup(&_ctx);
	}

	void init(const uint8_t *key, size_t sz_key) throw ()
	{
		HMAC_Init_ex(&_ctx, key, sz_key, _evp, 0);
		_valid = true;
	}
	void add(const uint8_t *buf, size_t sz) throw ()
	{
		if (!_valid) return;
		HMAC_Update(&_ctx, buf, sz);
	}
	void end(uint8_t *buf) throw ()
	{
		if (!_valid) return;

		unsigned len = SIZE;
		HMAC_Final(&_ctx, buf, &len);
		_valid = false;
	}
	size_t length() const
	{	return SIZE; }

private:
	HMAC_CTX _ctx;
	const EVP_MD *_evp;
	bool _valid;
};

// users probably shouldn't use this, but it's here more for completeness
typedef Hash_ssl<
    MD5_CTX, MD5_Init, MD5_Update, MD5_Final,
    MD5_DIGEST_LENGTH>
    Hash_md5;

// RIPEMD160
typedef Hash_ssl<
    RIPEMD160_CTX, RIPEMD160_Init, RIPEMD160_Update, RIPEMD160_Final,
    RIPEMD160_DIGEST_LENGTH>
    Hash_ripemd160;

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
							Hmac_ripemd160;
typedef Hmac_ssl<EVP_sha1, SHA_DIGEST_LENGTH>		Hmac_sha1;
typedef Hmac_ssl<EVP_sha224, SHA224_DIGEST_LENGTH>	Hmac_sha224;
typedef Hmac_ssl<EVP_sha256, SHA256_DIGEST_LENGTH>	Hmac_sha256;
typedef Hmac_ssl<EVP_sha384, SHA384_DIGEST_LENGTH>	Hmac_sha384;
typedef Hmac_ssl<EVP_sha512, SHA512_DIGEST_LENGTH>	Hmac_sha512;

}

#endif
