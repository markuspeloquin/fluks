#include <map>

#include "support.hpp"

namespace luks {
namespace {

std::string blank = "";

struct cipher_stat {
	std::string kern_name;
	uint16_t blocksize;
	uint16_t keymin;
	uint16_t keymax;
	uint16_t keystep;
	uint16_t version;
};

struct hash_stat {
	std::string kern_name;
	uint16_t blocksize;
	uint16_t digestsize;
	uint16_t version;
};

struct block_mode_stat {
	std::string kern_name;
	uint16_t version;
};

struct iv_mode_stat {
	std::string kern_name;
	uint16_t version;
};

/** Singleton class, constructs mappings for names and properties */
class Lookup {
public:
	static Lookup *instance()
	{	return &_instance; }

private:
	template <class Res, class Map, typename Enum>
	Res *stat_lookup(Map &map, Enum type)
	{
		typename Map::iterator i;
		i = map.find(type);
		if (i == map.end()) return 0;
		return &i->second;
	}
	template <class Map, typename Enum>
	Enum enum_lookup(Map &map, Enum def, const std::string &name)
	{
		typename Map::iterator i;
		i = map.find(name);
		if (i == map.end()) return def;
		return i->second;
	}
	template <class Map, typename Vec>
	void types(Map &map, Vec &types)
	{
		for (typename Map::iterator i = map.begin();
		    i != map.end(); ++i)
			types.push_back(i->first);
	}

public:
	struct cipher_stat	*stat_lookup(enum cipher_type type)
	{
		return stat_lookup<struct cipher_stat>(
		    cipher_stat_map, type);
	}
	struct hash_stat	*stat_lookup(enum hash_type type)
	{
		return stat_lookup<struct hash_stat>(
		    hash_stat_map, type);
	}
	struct block_mode_stat	*stat_lookup(enum block_mode mode)
	{
		return stat_lookup<struct block_mode_stat>(
		    block_mode_stat_map, mode);
	}
	struct iv_mode_stat	*stat_lookup(enum iv_mode mode)
	{
		return stat_lookup<struct iv_mode_stat>(
		    iv_mode_stat_map, mode);
	}

	enum cipher_type	cipher_lookup(const std::string &name)
	{
		return enum_lookup(cipher_name_map, CT_UNDEFINED, name);
	}
	enum hash_type		hash_lookup(const std::string &name)
	{
		return enum_lookup(hash_name_map, HT_UNDEFINED, name);
	}
	enum block_mode		block_mode_lookup(const std::string &name)
	{
		return enum_lookup(block_mode_name_map, BM_UNDEFINED, name);
	}
	enum iv_mode		iv_mode_lookup(const std::string &name)
	{
		return enum_lookup(iv_mode_name_map, IM_UNDEFINED, name);
	}

	void	cipher_types(std::vector<enum cipher_type> &vec)
	{	types(cipher_stat_map, vec); }
	void	hash_types(std::vector<enum hash_type> &vec)
	{	types(hash_stat_map, vec); }
	void	block_mode_types(std::vector<enum block_mode> &vec)
	{	types(block_mode_stat_map, vec); }
	void	iv_mode_types(std::vector<enum iv_mode> &vec)
	{	types(iv_mode_stat_map, vec); }

private:
	std::map<enum cipher_type, struct cipher_stat> cipher_stat_map;
	std::map<enum hash_type, struct hash_stat> hash_stat_map;
	std::map<enum block_mode, struct block_mode_stat> block_mode_stat_map;
	std::map<enum iv_mode, struct iv_mode_stat> iv_mode_stat_map;

	std::map<std::string, enum cipher_type> cipher_name_map;
	std::map<std::string, enum hash_type> hash_name_map;
	std::map<std::string, enum block_mode> block_mode_name_map;
	std::map<std::string, enum iv_mode> iv_mode_name_map;

	Lookup();

	Lookup(const Lookup &) {}
	void operator=(const Lookup &) {}

	static Lookup _instance;
};

Lookup Lookup::_instance;

Lookup::Lookup()
{
	cipher_stat_map[CT_AES] = (cipher_stat){ "aes", 16, 16, 32, 8, 1 };
	cipher_stat_map[CT_BLOWFISH] = (cipher_stat){ "blowfish", 8, 4, 56, 1, 0 };
	cipher_stat_map[CT_CAST5] = (cipher_stat){ "cast5", 8, 5, 16, 1, 1 };
//	cipher_stat_map[CT_CAST6] = (cipher_stat){ "cast6", 8, 16, 32, 8, 1 };
//	cipher_stat_map[CT_DES3] = (cipher_stat){ "des3_ede", 8, 24, 24, 0, 0 };
	cipher_stat_map[CT_SERPENT] = (cipher_stat){ "serpent", 16, 0, 32, 8, 1 };
	cipher_stat_map[CT_TWOFISH] = (cipher_stat){ "twofish", 16, 16, 32, 8, 1 };

	cipher_name_map["aes"] = CT_AES;
	cipher_name_map["blowfish"] = CT_BLOWFISH;
	cipher_name_map["cast5"] = CT_CAST5;
//	cipher_name_map["cast6"] = CT_CAST6;
//	cipher_name_map["des3"] = CT_DES3;
//	cipher_name_map["3des"] = CT_DES3;
//	cipher_name_map["des3_ede"] = CT_DES3;
//	cipher_name_map["3des_ede"] = CT_DES3;
	cipher_name_map["serpent"] = CT_SERPENT;
	cipher_name_map["twofish"] = CT_TWOFISH;

	hash_stat_map[HT_MD5] = (hash_stat){ "md5", 64, 16, 0 };
	hash_stat_map[HT_RMD160] = (hash_stat){ "rmd160", 64, 20, 1 };
	hash_stat_map[HT_SHA1] = (hash_stat){ "sha1", 64, 20, 1 };
	hash_stat_map[HT_SHA224] = (hash_stat){ "sha224", 64, 28, 0 };
	hash_stat_map[HT_SHA256] = (hash_stat){ "sha256", 64, 32, 1 };
	hash_stat_map[HT_SHA384] = (hash_stat){ "sha384", 128, 48, 0 };
	hash_stat_map[HT_SHA512] = (hash_stat){ "sha512", 128, 64, 1 };
	hash_stat_map[HT_TIGER128] = (hash_stat){ "tgr128", 64, 16, 0 };
	hash_stat_map[HT_TIGER160] = (hash_stat){ "tgr160", 64, 20, 0 };
	hash_stat_map[HT_TIGER192] = (hash_stat){ "tgr192", 64, 24, 0 };
	hash_stat_map[HT_WHIRLPOOL256] = (hash_stat){ "wp256", 64, 32, 0 };
	hash_stat_map[HT_WHIRLPOOL384] = (hash_stat){ "wp384", 64, 48, 0 };
	hash_stat_map[HT_WHIRLPOOL512] = (hash_stat){ "wp512", 64, 64, 0 };

	hash_name_map["md5"] = HT_MD5;
	hash_name_map["rmd160"] = HT_RMD160;
	hash_name_map["ripemd160"] = HT_RMD160;
	hash_name_map["sha"] = HT_SHA1;
	hash_name_map["sha1"] = HT_SHA1;
	hash_name_map["sha224"] = HT_SHA224;
	hash_name_map["sha256"] = HT_SHA256;
	hash_name_map["sha384"] = HT_SHA384;
	hash_name_map["sha512"] = HT_SHA512;
	hash_name_map["tiger128"] = HT_TIGER128;
	hash_name_map["tgr128"] = HT_TIGER128;
	hash_name_map["tiger160"] = HT_TIGER160;
	hash_name_map["tgr160"] = HT_TIGER160;
	hash_name_map["tiger"] = HT_TIGER192;
	hash_name_map["tgr"] = HT_TIGER192;
	hash_name_map["tiger192"] = HT_TIGER192;
	hash_name_map["tgr192"] = HT_TIGER192;
	hash_name_map["whirlpool256"] = HT_WHIRLPOOL256;
	hash_name_map["wp256"] = HT_WHIRLPOOL256;
	hash_name_map["whirlpool384"] = HT_WHIRLPOOL384;
	hash_name_map["wp384"] = HT_WHIRLPOOL384;
	hash_name_map["whirlpool512"] = HT_WHIRLPOOL512;
	hash_name_map["wp512"] = HT_WHIRLPOOL512;

	block_mode_stat_map[BM_CBC] = (block_mode_stat){ "cbc", 1 };
	block_mode_stat_map[BM_CTR] = (block_mode_stat){ "ctr", 0 };
	block_mode_stat_map[BM_ECB] = (block_mode_stat){ "ecb", 1 };
	block_mode_stat_map[BM_PCBC] = (block_mode_stat){ "pcbc", 0 };

	block_mode_name_map["cbc"] = BM_CBC;
	block_mode_name_map["ctr"] = BM_CTR;
	block_mode_name_map["ecb"] = BM_ECB;
	block_mode_name_map["pcbc"] = BM_PCBC;

	iv_mode_stat_map[IM_ESSIV] = (iv_mode_stat){ "essiv", 1 };
	iv_mode_stat_map[IM_PLAIN] = (iv_mode_stat){ "plain", 1 };

	iv_mode_name_map["essiv"] = IM_ESSIV;
	iv_mode_name_map["plain"] = IM_PLAIN;
}

} // end anon namespace
}

enum luks::cipher_type
luks::cipher_info::type(const std::string &name)
{
	return Lookup::instance()->cipher_lookup(name);
}

std::vector<enum luks::cipher_type>
luks::cipher_info::types()
{
	std::vector<enum cipher_type> res;
	Lookup::instance()->cipher_types(res);
	return res;
}

const std::string &
luks::cipher_info::name(enum cipher_type type)
{
	struct cipher_stat *st = Lookup::instance()->stat_lookup(type);
	return st ? st->kern_name : blank;
}

uint16_t
luks::cipher_info::block_size(enum cipher_type type)
{
	struct cipher_stat *st = Lookup::instance()->stat_lookup(type);
	return st ? st->blocksize : 0;
}

std::vector<uint16_t>
luks::cipher_info::key_sizes(enum cipher_type type)
{
	struct cipher_stat *st = Lookup::instance()->stat_lookup(type);
	if (!st) return std::vector<uint16_t>();
	std::vector<uint16_t> res;
	for (uint16_t s = st->keymin; s <= st->keymax; s += st->keystep)
		res.push_back(s);
	return res;
}

uint16_t
luks::cipher_info::version(enum cipher_type type)
{
	struct cipher_stat *st = Lookup::instance()->stat_lookup(type);
	return st ? st->version : 0;
}

enum luks::hash_type
luks::hash_info::type(const std::string &name)
{
	return Lookup::instance()->hash_lookup(name);
}

std::vector<enum luks::hash_type>
luks::hash_info::types()
{
	std::vector<enum hash_type> res;
	Lookup::instance()->hash_types(res);
	return res;
}

const std::string &
luks::hash_info::name(enum hash_type type)
{
	struct hash_stat *st = Lookup::instance()->stat_lookup(type);
	return st ? st->kern_name : blank;
}

size_t
luks::hash_info::digest_size(enum hash_type type)
{
	struct hash_stat *st = Lookup::instance()->stat_lookup(type);
	return st ? st->digestsize : 0;
}

size_t
luks::hash_info::block_size(enum hash_type type)
{
	struct hash_stat *st = Lookup::instance()->stat_lookup(type);
	return st ? st->blocksize : 0;
}

uint16_t
luks::hash_info::version(enum hash_type type)
{
	struct hash_stat *st = Lookup::instance()->stat_lookup(type);
	return st ? st->version : 0;
}

enum luks::block_mode
luks::block_mode_info::type(const std::string &name)
{
	return Lookup::instance()->block_mode_lookup(name);
}

std::vector<enum luks::block_mode>
luks::block_mode_info::types()
{
	std::vector<enum block_mode> res;
	Lookup::instance()->block_mode_types(res);
	return res;
}

const std::string &
luks::block_mode_info::name(enum block_mode mode)
{
	struct block_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->kern_name : blank;
}

uint16_t
luks::block_mode_info::version(enum block_mode mode)
{
	struct block_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->version : 0;
}

enum luks::iv_mode
luks::iv_mode_info::type(const std::string &name)
{
	return Lookup::instance()->iv_mode_lookup(name);
}

std::vector<enum luks::iv_mode>
luks::iv_mode_info::types()
{
	std::vector<enum iv_mode> res;
	Lookup::instance()->iv_mode_types(res);
	return res;
}

const std::string &
luks::iv_mode_info::name(enum iv_mode mode)
{
	struct iv_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->kern_name : blank;
}

uint16_t
luks::iv_mode_info::version(enum iv_mode mode)
{
	struct iv_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->version : 0;
}
