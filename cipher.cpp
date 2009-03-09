#include <stdint.h>

#include <map>

#include "cipher.hpp"

namespace luks {
namespace {

struct cipher_stat {
	std::string kern_name;
	uint16_t blocksize;
	uint16_t keymin;
	uint16_t keymax;
	uint16_t keystep;

};

/** Singleton class, constructs mappings for cipher names and properties */
class Lookup {
public:
	static const Lookup *instance()
	{	return &_instance; }

	std::map<enum cipher_type, struct cipher_stat> type2str;
	std::map<std::string, enum cipher_type> str2type;
private:
	Lookup();

	Lookup(const Lookup &l) {}
	void operator=(const Lookup &l) {}

	static Lookup _instance;
};

Lookup::Lookup()
{
	type2str[CT_AES] = (cipher_stat){ "aes", 16, 16, 32, 8 };
	type2str[CT_BLOWFISH] = (cipher_stat){ "blowfish", 8, 4, 56, 1 };
	type2str[CT_CAST5] = (cipher_stat){ "cast5", 8, 5, 16, 1 };
	type2str[CT_CAST6] = (cipher_stat){ "cast5", 8, 16, 32, 8 };
//	type2str[CT_DES3] = (cipher_stat){ "des3_ede", 8, 24, 24, 0 };
	type2str[CT_SERPENT] = (cipher_stat){ "serpent", 16, 0, 32, 8 };
	type2str[CT_TWOFISH] = (cipher_stat){ "twofish", 16, 16, 32, 8 };

	str2type["aes"] = CT_AES;
	str2type["blowfish"] = CT_BLOWFISH;
	str2type["cast5"] = CT_CAST5;
	str2type["cast6"] = CT_CAST6;
//	str2type["des3"] = CT_DES3;
//	str2type["3des"] = CT_DES3;
//	str2type["des3_ede"] = CT_DES3;
//	str2type["3des_ede"] = CT_DES3;
	str2type["serpent"] = CT_SERPENT;
	str2type["twofish"] = CT_TWOFISH;
}

Lookup Lookup::_instance;

} // end anon namespace
}

enum luks::cipher_type
luks::get_cipher_type(const std::string &name)
{
	typedef std::map<std::string, enum cipher_type>::const_iterator Iter;
	Iter i = Lookup::instance()->str2type.find(name);
	if (i == Lookup::instance()->str2type.end()) return CT_UNDEFINED;
	return i->second;
}

std::string
luks::cipher_name(enum cipher_type type)
{
	typedef std::map<enum cipher_type, struct cipher_stat>::const_iterator
	    Iter;
	Iter i = Lookup::instance()->type2str.find(type);
	if (i == Lookup::instance()->type2str.end()) return "";
	return i->second.kern_name;
}

uint16_t
luks::cipher_block_size(enum cipher_type type)
{
	typedef std::map<enum cipher_type, struct cipher_stat>::const_iterator
	    Iter;
	Iter i = Lookup::instance()->type2str.find(type);
	if (i == Lookup::instance()->type2str.end()) return 0;
	return i->second.blocksize;
}

std::vector<uint16_t>
luks::cipher_key_sizes(enum cipher_type type)
{
	typedef std::map<enum cipher_type, struct cipher_stat>::const_iterator
	    Iter;
	Iter i = Lookup::instance()->type2str.find(type);
	if (i == Lookup::instance()->type2str.end())
		return std::vector<uint16_t>();

	std::vector<uint16_t> res;
	res.push_back(i->second.keymin);
	while (res.back() < i->second.keymax)
		res.push_back(res.back() + i->second.keystep);
	return res;
}
