#include "hash.hpp"

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
		Assert(0, "Hash_function::create() bad hash type");
		return std::tr1::shared_ptr<Hash_function>();
	}
}
