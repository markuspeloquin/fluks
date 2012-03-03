/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <map>

#include "support.hpp"

namespace fluks {
namespace {

std::string blank = "";

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

	enum block_mode		block_mode_lookup(const std::string &name)
	{
		return enum_lookup(block_mode_name_map, BM_UNDEFINED, name);
	}
	enum iv_mode		iv_mode_lookup(const std::string &name)
	{
		return enum_lookup(iv_mode_name_map, IM_UNDEFINED, name);
	}

	void	block_mode_types(std::vector<enum block_mode> &vec)
	{	types(block_mode_stat_map, vec); }
	void	iv_mode_types(std::vector<enum iv_mode> &vec)
	{	types(iv_mode_stat_map, vec); }

private:
	std::map<enum block_mode, struct block_mode_stat> block_mode_stat_map;
	std::map<enum iv_mode, struct iv_mode_stat> iv_mode_stat_map;

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
	block_mode_stat_map[BM_CBC] = (block_mode_stat){ "cbc", 1 };
	block_mode_stat_map[BM_CFB] = (block_mode_stat){ "cfb", 0 };
	block_mode_stat_map[BM_CTR] = (block_mode_stat){ "ctr", 0 };
	block_mode_stat_map[BM_ECB] = (block_mode_stat){ "ecb", 1 };
	block_mode_stat_map[BM_OFB] = (block_mode_stat){ "ofb", 0 };
	block_mode_stat_map[BM_PCBC] = (block_mode_stat){ "pcbc", 0 };

	block_mode_name_map["cbc"] = BM_CBC;
	block_mode_name_map["cfb"] = BM_CFB;
	block_mode_name_map["ctr"] = BM_CTR;
	block_mode_name_map["ecb"] = BM_ECB;
	block_mode_name_map["ofb"] = BM_OFB;
	block_mode_name_map["pcbc"] = BM_PCBC;

	iv_mode_stat_map[IM_ESSIV] = (iv_mode_stat){ "essiv", 1 };
	iv_mode_stat_map[IM_PLAIN] = (iv_mode_stat){ "plain", 1 };

	iv_mode_name_map["essiv"] = IM_ESSIV;
	iv_mode_name_map["plain"] = IM_PLAIN;
}

} // end anon namespace
}

enum fluks::block_mode
fluks::block_mode_info::type(const std::string &name)
{
	return Lookup::instance()->block_mode_lookup(name);
}

std::vector<enum fluks::block_mode>
fluks::block_mode_info::types()
{
	std::vector<enum block_mode> res;
	Lookup::instance()->block_mode_types(res);
	return res;
}

const std::string &
fluks::block_mode_info::name(enum block_mode mode)
{
	struct block_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->kern_name : blank;
}

uint16_t
fluks::block_mode_info::version(enum block_mode mode)
{
	struct block_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->version : 0;
}

enum fluks::iv_mode
fluks::iv_mode_info::type(const std::string &name)
{
	return Lookup::instance()->iv_mode_lookup(name);
}

std::vector<enum fluks::iv_mode>
fluks::iv_mode_info::types()
{
	std::vector<enum iv_mode> res;
	Lookup::instance()->iv_mode_types(res);
	return res;
}

const std::string &
fluks::iv_mode_info::name(enum iv_mode mode)
{
	struct iv_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->kern_name : blank;
}

uint16_t
fluks::iv_mode_info::version(enum iv_mode mode)
{
	struct iv_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->version : 0;
}
