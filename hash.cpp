#include <cassert>
#include <map>

#include "hash.hpp"

namespace luks {
namespace {

struct hash_stat {
	std::string kern_name;
	uint16_t blocksize;
	uint16_t digestsize;
};

/** Singleton class, constructs mappings for hash names and properties */
class Lookup {
public:
	static const Lookup *instance()
	{	return &_instance; }

	std::map<enum hash_type, struct hash_stat> type2str;
	std::map<std::string, enum hash_type> str2type;
private:
	Lookup();

	Lookup(const Lookup &l) {}
	void operator=(const Lookup &l) {}

	static Lookup _instance;
};

Lookup::Lookup()
{
	type2str[HT_MD5] = (hash_stat){ "md5", 64, 16 };
	type2str[HT_RMD160] = (hash_stat){ "rmd160", 64, 20 };
	type2str[HT_SHA1] = (hash_stat){ "sha1", 64, 20 };
	type2str[HT_SHA224] = (hash_stat){ "sha224", 64, 28 };
	type2str[HT_SHA256] = (hash_stat){ "sha256", 64, 32 };
	type2str[HT_SHA384] = (hash_stat){ "sha384", 128, 48 };
	type2str[HT_SHA512] = (hash_stat){ "sha512", 128, 64 };
	type2str[HT_TIGER128] = (hash_stat){ "tgr128", 64, 16 };
	type2str[HT_TIGER160] = (hash_stat){ "tgr160", 64, 20 };
	type2str[HT_TIGER192] = (hash_stat){ "tgr", 64, 24 };
	type2str[HT_WHIRLPOOL256] = (hash_stat){ "wp256", 64, 32 };
	type2str[HT_WHIRLPOOL384] = (hash_stat){ "wp384", 64, 48 };
	type2str[HT_WHIRLPOOL512] = (hash_stat){ "wp512", 64, 64 };

	str2type["md5"] = HT_MD5;
	str2type["rmd160"] = HT_RMD160;
	str2type["ripemd160"] = HT_RMD160;
	str2type["sha"] = HT_SHA1;
	str2type["sha1"] = HT_SHA1;
	str2type["sha224"] = HT_SHA224;
	str2type["sha256"] = HT_SHA256;
	str2type["sha384"] = HT_SHA384;
	str2type["sha512"] = HT_SHA512;
	str2type["tiger128"] = HT_TIGER128;
	str2type["tgr128"] = HT_TIGER128;
	str2type["tiger160"] = HT_TIGER160;
	str2type["tgr160"] = HT_TIGER160;
	str2type["tiger"] = HT_TIGER192;
	str2type["tgr"] = HT_TIGER192;
	str2type["tiger192"] = HT_TIGER192;
	str2type["tgr192"] = HT_TIGER192;
	str2type["whirlpool256"] = HT_WHIRLPOOL256;
	str2type["wp256"] = HT_WHIRLPOOL256;
	str2type["whirlpool384"] = HT_WHIRLPOOL384;
	str2type["wp384"] = HT_WHIRLPOOL384;
	str2type["whirlpool512"] = HT_WHIRLPOOL512;
	str2type["wp512"] = HT_WHIRLPOOL512;
}

Lookup Lookup::_instance;

} // end anon namespace
}

enum luks::hash_type
luks::get_hash_type(const std::string &name)
{
	typedef std::map<std::string, enum hash_type>::const_iterator Iter;
	Iter i = Lookup::instance()->str2type.find(name);
	if (i == Lookup::instance()->str2type.end()) return HT_UNDEFINED;
	return i->second;
}

std::string
luks::hash_name(enum hash_type type)
{
	typedef std::map<enum hash_type, struct hash_stat>::const_iterator
	    Iter;
	Iter i = Lookup::instance()->type2str.find(type);
	if (i == Lookup::instance()->type2str.end()) return "";
	return i->second.kern_name;
}

size_t
luks::hash_digest_size(enum hash_type type)
{
	typedef std::map<enum hash_type, struct hash_stat>::const_iterator
	    Iter;
	Iter i = Lookup::instance()->type2str.find(type);
	if (i == Lookup::instance()->type2str.end()) return 0;
	return i->second.digestsize;
}

size_t
luks::hash_block_size(enum hash_type type)
{
	typedef std::map<enum hash_type, struct hash_stat>::const_iterator
	    Iter;
	Iter i = Lookup::instance()->type2str.find(type);
	if (i == Lookup::instance()->type2str.end()) return 0;
	return i->second.blocksize;
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
