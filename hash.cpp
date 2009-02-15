#include <cassert>

#include "hash.hpp"

enum luks::hash_type
luks::hash_type(const std::string &name)
{
	if (name == "md5") return HT_MD5;
	if (name == "ripemd160") return HT_RIPEMD160;
	if (name == "sha" || name == "sha1") return HT_SHA1;
	if (name == "sha224") return HT_SHA224;
	if (name == "sha256") return HT_SHA256;
	if (name == "sha384") return HT_SHA384;
	if (name == "sha512") return HT_SHA512;
	return HT_UNDEFINED;
}

std::string
luks::hash_name(enum hash_type type)
{
	switch (type) {
	case HT_MD5:	return "md5";
	case HT_RIPEMD160:	return "ripemd160";
	case HT_SHA1:	return "sha1";
	case HT_SHA224:	return "sha224";
	case HT_SHA256:	return "sha256";
	case HT_SHA384:	return "sha384";
	case HT_SHA512:	return "sha512";
	default:	assert(0);
			return "undefined";
	}
}

size_t
luks::hash_size(enum hash_type type)
{
	switch (type) {
	case HT_MD5:	return MD5_DIGEST_LENGTH;
	case HT_RIPEMD160:	return RIPEMD160_DIGEST_LENGTH;
	case HT_SHA1:	return SHA_DIGEST_LENGTH;
	case HT_SHA224:	return SHA224_DIGEST_LENGTH;
	case HT_SHA256:	return SHA256_DIGEST_LENGTH;
	case HT_SHA384:	return SHA384_DIGEST_LENGTH;
	case HT_SHA512:	return SHA512_DIGEST_LENGTH;
	default:	assert(0);
			return 0;
	}
}

std::tr1::shared_ptr<luks::Hash_function>
luks::Hash_function::create(enum hash_type type)
{
	switch (type) {
	case HT_MD5:
		return std::tr1::shared_ptr<Hash_function>(new Hash_md5);
	case HT_RIPEMD160:
		return std::tr1::shared_ptr<Hash_function>(new Hash_ripemd160);
	case HT_SHA1:
		return std::tr1::shared_ptr<Hash_function>(new Hash_sha1);
	case HT_SHA224:
		return std::tr1::shared_ptr<Hash_function>(new Hash_sha224);
	case HT_SHA256:
		return std::tr1::shared_ptr<Hash_function>(new Hash_sha256);
	case HT_SHA384:
		return std::tr1::shared_ptr<Hash_function>(new Hash_sha384);
	case HT_SHA512:
		return std::tr1::shared_ptr<Hash_function>(new Hash_sha512);
	default:
		assert(0);
		return std::tr1::shared_ptr<Hash_function>();
	}
}

std::tr1::shared_ptr<luks::Hmac_function>
luks::Hmac_function::create(enum hash_type type)
{
	switch (type) {
	case HT_MD5:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_md5);
	case HT_RIPEMD160:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_ripemd160);
	case HT_SHA1:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_sha1);
	case HT_SHA224:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_sha224);
	case HT_SHA256:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_sha256);
	case HT_SHA384:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_sha384);
	case HT_SHA512:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_sha512);
	default:
		assert(0);
		return std::tr1::shared_ptr<Hmac_function>();
	}
}
