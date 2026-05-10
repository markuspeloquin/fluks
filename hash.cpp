#include <map>

#include "hash.hpp"

namespace fluks {
namespace {

class Lookup {
public:
	static const Hash_traits *traits(hash_type type);
	static hash_type type(std::string_view name);

	static const std::vector<hash_type> &types() {
		return inst._types;
	}

private:
	Lookup();
	Lookup(const Lookup &) {}
	void operator=(const Lookup &) {}

	static Lookup inst;
	std::map<hash_type, Hash_traits> _map_traits;
	std::map<std::string, hash_type, std::less<>>_map_type;
	std::vector<hash_type> _types;
};

const Hash_traits *
Lookup::traits(hash_type type) {
	auto it = inst._map_traits.find(type);
	if (it == inst._map_traits.end()) return 0;
	return &it->second;
}

hash_type
Lookup::type(std::string_view name) {
	auto it = inst._map_type.find(name);
	if (it == inst._map_type.end()) return hash_type::UNDEFINED;
	return it->second;
}

Lookup::Lookup() {
	// name, blocksize, digestsize, LUKS version
	_map_traits[hash_type::MD5] = Hash_traits("md5", 64, 16, 0);
	_map_traits[hash_type::RMD160] = Hash_traits("rmd160", 64, 20, 1);
	_map_traits[hash_type::SHA1] = Hash_traits("sha1", 64, 20, 1);
	_map_traits[hash_type::SHA224] = Hash_traits("sha224", 64, 28, 0);
	_map_traits[hash_type::SHA256] = Hash_traits("sha256", 64, 32, 1);
	_map_traits[hash_type::SHA384] = Hash_traits("sha384", 128, 48, 0);
	_map_traits[hash_type::SHA512] = Hash_traits("sha512", 128, 64, 1);
	_map_traits[hash_type::TIGER128] = Hash_traits("tgr128", 64, 16, 0);
	_map_traits[hash_type::TIGER160] = Hash_traits("tgr160", 64, 20, 0);
	_map_traits[hash_type::TIGER192] = Hash_traits("tgr192", 64, 24, 0);
	_map_traits[hash_type::WHIRLPOOL256] = Hash_traits("wp256", 64, 32, 0);
	_map_traits[hash_type::WHIRLPOOL384] = Hash_traits("wp384", 64, 48, 0);
	_map_traits[hash_type::WHIRLPOOL512] = Hash_traits("wp512", 64, 64, 0);

	_map_type["md5"] = hash_type::MD5;
	_map_type["rmd160"] = hash_type::RMD160;
	_map_type["ripemd160"] = hash_type::RMD160;
	_map_type["sha"] = hash_type::SHA1;
	_map_type["sha1"] = hash_type::SHA1;
	_map_type["sha224"] = hash_type::SHA224;
	_map_type["sha256"] = hash_type::SHA256;
	_map_type["sha384"] = hash_type::SHA384;
	_map_type["sha512"] = hash_type::SHA512;
	_map_type["tiger128"] = hash_type::TIGER128;
	_map_type["tgr128"] = hash_type::TIGER128;
	_map_type["tiger160"] = hash_type::TIGER160;
	_map_type["tgr160"] = hash_type::TIGER160;
	_map_type["tiger"] = hash_type::TIGER192;
	_map_type["tgr"] = hash_type::TIGER192;
	_map_type["tiger192"] = hash_type::TIGER192;
	_map_type["tgr192"] = hash_type::TIGER192;
	_map_type["whirlpool256"] = hash_type::WHIRLPOOL256;
	_map_type["wp256"] = hash_type::WHIRLPOOL256;
	_map_type["whirlpool384"] = hash_type::WHIRLPOOL384;
	_map_type["wp384"] = hash_type::WHIRLPOOL384;
	_map_type["whirlpool512"] = hash_type::WHIRLPOOL512;
	_map_type["wp512"] = hash_type::WHIRLPOOL512;
	_map_type["whirlpool"] = hash_type::WHIRLPOOL512;
	_map_type["wp"] = hash_type::WHIRLPOOL512;

	for (auto &[hash_type, _] : _map_traits)
		_types.push_back(hash_type);
}

Lookup Lookup::inst;

} // end anon namespace
}

std::shared_ptr<fluks::Hash_function>
fluks::Hash_function::create(hash_type type) {
	switch (type) {
	case hash_type::MD5:
		return std::shared_ptr<Hash_function>(new Hash_md5);
	case hash_type::RMD160:
		return std::shared_ptr<Hash_function>(new Hash_rmd160);
	case hash_type::SHA1:
		return std::shared_ptr<Hash_function>(new Hash_sha1);
	case hash_type::SHA224:
		return std::shared_ptr<Hash_function>(new Hash_sha224);
	case hash_type::SHA256:
		return std::shared_ptr<Hash_function>(new Hash_sha256);
	case hash_type::SHA384:
		return std::shared_ptr<Hash_function>(new Hash_sha384);
	case hash_type::SHA512:
		return std::shared_ptr<Hash_function>(new Hash_sha512);
	case hash_type::TIGER128:
	case hash_type::TIGER160:
	case hash_type::TIGER192:
		return std::shared_ptr<Hash_function>(new Hash_tiger(type));
	case hash_type::WHIRLPOOL256:
	case hash_type::WHIRLPOOL384:
	case hash_type::WHIRLPOOL512:
		return std::shared_ptr<Hash_function>(
		    new Hash_whirlpool(type));
	default:
		Assert(0, "Hash_function::create() bad hash type");
		return std::shared_ptr<Hash_function>();
	}
}

const fluks::Hash_traits *
fluks::Hash_traits::traits(hash_type type) {
	return Lookup::traits(type);
}

fluks::hash_type
fluks::Hash_traits::type(std::string_view name) {
	return Lookup::type(name);
}

const std::vector<fluks::hash_type> &
fluks::Hash_traits::types() {
	return Lookup::types();
}
