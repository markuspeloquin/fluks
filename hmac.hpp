#ifndef FLUKS_HMAC_HPP
#define FLUKS_HMAC_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <openssl/params.h>
#include <string_view>

#include <openssl/evp.h>
#include <openssl/params.h>

#include "hash.hpp"

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
	[[nodiscard]]
	static std::shared_ptr<Hmac_function> create(std::string_view name) {
		return create(Hash_traits::type(name));
	}

	/**
	 * Create an HMAC function, in an abstract sense, given a hash type.
	 *
	 * \param type	The hash algorithm.
	 * \return	An HMAC function pointer.
	 */
	[[nodiscard]]
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
	const Hash_traits *traits() const {
		return _traits;
	}

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

	void init(const uint8_t *key, size_t sz);
	void add(const uint8_t *buf, size_t sz) {
		_hashfn->add(buf, sz);
	}
	void end(uint8_t *out);

private:
	Hmac_impl(const Hmac_impl &) : Hmac_function(0) {}
	void operator=(const Hmac_impl &) {}

	std::shared_ptr<Hash_function>	_hashfn;
	std::unique_ptr<uint8_t>	_key;
};


/** OpenSSL HMAC function template */
template <hash_type type>
class Hmac_evp : public Hmac_function {
public:
	Hmac_evp() :
		Hmac_function(type),
		_valid(false)
	{
		EVP_MAC *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
		if (!mac)
			throw Ssl_error("EVP_MAC_fetch(\"HMAC\")) failed");
		_ctx = EVP_MAC_CTX_new(mac);
		if (!_ctx)
			throw Ssl_error("EVP_MAC_CTX_new() failed");
	}

	~Hmac_evp() noexcept {
		EVP_MAC_CTX_free(_ctx);
	}

	void init(const uint8_t *key, size_t sz) {
		OSSL_PARAM params[] = {
			OSSL_PARAM_construct_utf8_string(
			    "digest", const_cast<char *>(digest_name()), 0
			),
			OSSL_PARAM_END,
		};
		if (!EVP_MAC_init(_ctx, key, sz, params))
			throw Ssl_error("EVP_MAC_init() failed");
		_valid = true;
	}

	void add(const uint8_t *data, size_t sz) {
		if (!_valid) return;
		if (!EVP_MAC_update(_ctx, data, sz))
			throw Ssl_error("EVP_MAC_update() failed");
	}

	void end(uint8_t *out) {
		if (!_valid) return;
		unsigned sz = traits()->digest_size;
		if (!EVP_MAC_final(_ctx, out, nullptr, sz))
			throw Ssl_error("EVP_MAC_final() failed");
		_valid = false;
	}

private:
	constexpr const char *digest_name() {
		switch (type) {
		case hash_type::MD5:    return "MD5";
		case hash_type::RMD160: return "RIPEMD160";
		case hash_type::SHA1:   return "SHA1";
		case hash_type::SHA224: return "SHA224";
		case hash_type::SHA256: return "SHA256";
		case hash_type::SHA384: return "SHA384";
		case hash_type::SHA512: return "SHA512";
		default:
			static_assert(type == type, "unexpected type");
		}
	}

	EVP_MAC_CTX	*_ctx;
	bool		_valid;
};


typedef Hmac_evp<hash_type::MD5>	Hmac_md5;
typedef Hmac_evp<hash_type::RMD160>	Hmac_rmd160;
typedef Hmac_evp<hash_type::SHA1>	Hmac_sha1;
typedef Hmac_evp<hash_type::SHA224>	Hmac_sha224;
typedef Hmac_evp<hash_type::SHA256>	Hmac_sha256;
typedef Hmac_evp<hash_type::SHA384>	Hmac_sha384;
typedef Hmac_evp<hash_type::SHA512>	Hmac_sha512;


}

#endif
