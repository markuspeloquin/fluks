/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <map>

#include "hash.hpp"

namespace fluks {
namespace {

class Lookup {
public:
	static const Hash_info *info(enum hash_type type);
	static enum hash_type type(const std::string &name);
	static const std::vector<enum hash_type> &types()
	{	return inst._types; }
private:
	Lookup();
	Lookup(const Lookup &) {}
	void operator=(const Lookup &) {}

	static Lookup inst;
	std::map<enum hash_type, Hash_info> _map_info;
	std::map<std::string, enum hash_type> _map_type;
	std::vector<enum hash_type> _types;
};

const Hash_info *
Lookup::info(enum hash_type type)
{
	std::map<enum hash_type, Hash_info>::iterator i;
	i = inst._map_info.find(type);
	if (i == inst._map_info.end()) return 0;
	return &i->second;
}

enum hash_type
Lookup::type(const std::string &name)
{
	std::map<std::string, enum hash_type>::iterator i;
	i = inst._map_type.find(name);
	if (i == inst._map_type.end()) return HT_UNDEFINED;
	return i->second;
}

Lookup::Lookup()
{
	_map_info[HT_MD5] = Hash_info("md5", 64, 16, 0);
	_map_info[HT_RMD160] = Hash_info("rmd160", 64, 20, 1);
	_map_info[HT_SHA1] = Hash_info("sha1", 64, 20, 1);
	_map_info[HT_SHA224] = Hash_info("sha224", 64, 28, 0);
	_map_info[HT_SHA256] = Hash_info("sha256", 64, 32, 1);
	_map_info[HT_SHA384] = Hash_info("sha384", 128, 48, 0);
	_map_info[HT_SHA512] = Hash_info("sha512", 128, 64, 1);
	_map_info[HT_TIGER128] = Hash_info("tgr128", 64, 16, 0);
	_map_info[HT_TIGER160] = Hash_info("tgr160", 64, 20, 0);
	_map_info[HT_TIGER192] = Hash_info("tgr192", 64, 24, 0);
	_map_info[HT_WHIRLPOOL256] = Hash_info("wp256", 64, 32, 0);
	_map_info[HT_WHIRLPOOL384] = Hash_info("wp384", 64, 48, 0);
	_map_info[HT_WHIRLPOOL512] = Hash_info("wp512", 64, 64, 0);

	_map_type["md5"] = HT_MD5;
	_map_type["rmd160"] = HT_RMD160;
	_map_type["ripemd160"] = HT_RMD160;
	_map_type["sha"] = HT_SHA1;
	_map_type["sha1"] = HT_SHA1;
	_map_type["sha224"] = HT_SHA224;
	_map_type["sha256"] = HT_SHA256;
	_map_type["sha384"] = HT_SHA384;
	_map_type["sha512"] = HT_SHA512;
	_map_type["tiger128"] = HT_TIGER128;
	_map_type["tgr128"] = HT_TIGER128;
	_map_type["tiger160"] = HT_TIGER160;
	_map_type["tgr160"] = HT_TIGER160;
	_map_type["tiger"] = HT_TIGER192;
	_map_type["tgr"] = HT_TIGER192;
	_map_type["tiger192"] = HT_TIGER192;
	_map_type["tgr192"] = HT_TIGER192;
	_map_type["whirlpool256"] = HT_WHIRLPOOL256;
	_map_type["wp256"] = HT_WHIRLPOOL256;
	_map_type["whirlpool384"] = HT_WHIRLPOOL384;
	_map_type["wp384"] = HT_WHIRLPOOL384;
	_map_type["whirlpool512"] = HT_WHIRLPOOL512;
	_map_type["wp512"] = HT_WHIRLPOOL512;

	for (std::map<enum hash_type, Hash_info>::iterator i =
	    _map_info.begin(); i != _map_info.end(); ++i)
		_types.push_back(i->first);
}

Lookup Lookup::inst;

} // end anon namespace
}

std::tr1::shared_ptr<fluks::Hash_function>
fluks::Hash_function::create(enum hash_type type)
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
		    new Hash_tiger(type));
	case HT_TIGER160:
		return std::tr1::shared_ptr<Hash_function>(
		    new Hash_tiger(type));
	case HT_TIGER192:
		return std::tr1::shared_ptr<Hash_function>(
		    new Hash_tiger(type));
	case HT_WHIRLPOOL256:
		return std::tr1::shared_ptr<Hash_function>(
		    new Hash_whirlpool(type));
	case HT_WHIRLPOOL384:
		return std::tr1::shared_ptr<Hash_function>(
		    new Hash_whirlpool(type));
	case HT_WHIRLPOOL512:
		return std::tr1::shared_ptr<Hash_function>(
		    new Hash_whirlpool(type));
	default:
		Assert(0, "Hash_function::create() bad hash type");
		return std::tr1::shared_ptr<Hash_function>();
	}
}

const fluks::Hash_info *
fluks::Hash_info::info(enum hash_type type)
{
	return Lookup::info(type);
}

enum fluks::hash_type
fluks::Hash_info::type(const std::string &name)
{
	return Lookup::type(name);
}

const std::vector<enum fluks::hash_type> &
fluks::Hash_info::types()
{
	return Lookup::types();
}
