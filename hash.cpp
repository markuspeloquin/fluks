#include <cassert>

#include "hash.hpp"

enum luks::hash_type
luks::hash_type(const std::string &name)
{
	if (name == "md5")	return HT_MD5;
	if (name == "rmd160" || name == "ripemd160")	return HT_RMD160;
	if (name == "sha" || name == "sha1")	return HT_SHA1;
	if (name == "sha224")	return HT_SHA224;
	if (name == "sha256")	return HT_SHA256;
	if (name == "sha384")	return HT_SHA384;
	if (name == "sha512")	return HT_SHA512;
	if (name == "tiger128")	return HT_TIGER128;
	if (name == "tiger160")	return HT_TIGER160;
	if (name == "tiger" || name == "tiger192")	return HT_TIGER192;
	else			return HT_UNDEFINED;
}

std::string
luks::hash_name(enum hash_type type)
{
	switch (type) {
	case HT_MD5:	return "md5";
	case HT_RMD160:	return "rmd160";
	case HT_SHA1:	return "sha1";
	case HT_SHA224:	return "sha224";
	case HT_SHA256:	return "sha256";
	case HT_SHA384:	return "sha384";
	case HT_SHA512:	return "sha512";
	case HT_TIGER128:	return "tiger128";
	case HT_TIGER160:	return "tiger160";
	case HT_TIGER192:	return "tiger";
	default:	assert(0);
			return "undefined";
	}
}

size_t
luks::hash_size(enum hash_type type)
{
	switch (type) {
	case HT_MD5:	return MD5_DIGEST_LENGTH;
	case HT_RMD160:	return RIPEMD160_DIGEST_LENGTH;
	case HT_SHA1:	return SHA_DIGEST_LENGTH;
	case HT_SHA224:	return SHA224_DIGEST_LENGTH;
	case HT_SHA256:	return SHA256_DIGEST_LENGTH;
	case HT_SHA384:	return SHA384_DIGEST_LENGTH;
	case HT_SHA512:	return SHA512_DIGEST_LENGTH;
	case HT_TIGER128:	return TIGER128_SZ_DIGEST;
	case HT_TIGER160:	return TIGER160_SZ_DIGEST;
	case HT_TIGER192:	return TIGER_SZ_DIGEST;
	case HT_WHIRLPOOL256:	return WHIRLPOOL256_SZ_DIGEST;
	case HT_WHIRLPOOL384:	return WHIRLPOOL384_SZ_DIGEST;
	case HT_WHIRLPOOL512:	return WHIRLPOOL_SZ_DIGEST;
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
	case HT_RMD160:
		return std::tr1::shared_ptr<Hash_function>(new Hash_rmd160);
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
	case HT_TIGER128:
		return std::tr1::shared_ptr<Hash_function>(
		    new Hash_tiger(TIGER128_SZ_DIGEST));
	case HT_TIGER160:
		return std::tr1::shared_ptr<Hash_function>(
		    new Hash_tiger(TIGER160_SZ_DIGEST));
	case HT_TIGER192:
		return std::tr1::shared_ptr<Hash_function>(
		    new Hash_tiger(TIGER_SZ_DIGEST));
	case HT_WHIRLPOOL256:
		return std::tr1::shared_ptr<Hash_function>(
		    new Hash_whirlpool(WHIRLPOOL256_SZ_DIGEST));
	case HT_WHIRLPOOL384:
		return std::tr1::shared_ptr<Hash_function>(
		    new Hash_whirlpool(WHIRLPOOL384_SZ_DIGEST));
	case HT_WHIRLPOOL512:
		return std::tr1::shared_ptr<Hash_function>(
		    new Hash_whirlpool(WHIRLPOOL_SZ_DIGEST));
	default:
		assert(0);
		return std::tr1::shared_ptr<Hash_function>();
	}
}
