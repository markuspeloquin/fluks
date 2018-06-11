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

#include <algorithm>
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
	static Lookup *instance() {
		return &_instance;
	}

private:
	template <class Res, class Map, typename Enum>
	Res *stat_lookup(Map &map, Enum type)
	{
		auto i = map.find(type);
		if (i == map.end()) return 0;
		return &i->second;
	}

	template <class Map, typename Enum>
	Enum enum_lookup(Map &map, Enum def, const std::string &name) {
		auto i = map.find(name);
		if (i == map.end()) return def;
		return i->second;
	}

	template <class Map, typename Vec>
	void types(Map &map, Vec &types) {
		for (auto pair : map)
			types.push_back(pair.first);
	}

public:
	struct block_mode_stat	*stat_lookup(block_mode mode) {
		return stat_lookup<struct block_mode_stat>(
		    block_mode_stat_map, mode);
	}

	struct iv_mode_stat *stat_lookup(iv_mode mode) {
		return stat_lookup<struct iv_mode_stat>(
		    iv_mode_stat_map, mode);
	}

	block_mode block_mode_lookup(const std::string &name) {
		return enum_lookup(block_mode_name_map, block_mode::UNDEFINED,
		    name);
	}

	iv_mode iv_mode_lookup(const std::string &name) {
		return enum_lookup(iv_mode_name_map, iv_mode::UNDEFINED,
		    name);
	}

	void block_mode_types(std::vector<block_mode> &vec) {
		types(block_mode_stat_map, vec);
	}

	void iv_mode_types(std::vector<iv_mode> &vec) {
		types(iv_mode_stat_map, vec);
	}

private:
	std::map<block_mode, struct block_mode_stat> block_mode_stat_map;
	std::map<iv_mode, struct iv_mode_stat> iv_mode_stat_map;

	std::map<std::string, block_mode> block_mode_name_map;
	std::map<std::string, iv_mode> iv_mode_name_map;

	Lookup();

	Lookup(const Lookup &) {}
	void operator=(const Lookup &) {}

	static Lookup _instance;
};

Lookup Lookup::_instance;

Lookup::Lookup() {
	block_mode_stat_map[block_mode::CBC] = (block_mode_stat){ "cbc", 1 };
	block_mode_stat_map[block_mode::CBC_CTS] = (block_mode_stat){ "cts", 1 };
	block_mode_stat_map[block_mode::CFB] = (block_mode_stat){ "cfb", 0 };
	block_mode_stat_map[block_mode::CTR] = (block_mode_stat){ "ctr", 0 };
	block_mode_stat_map[block_mode::ECB] = (block_mode_stat){ "ecb", 1 };
	block_mode_stat_map[block_mode::OFB] = (block_mode_stat){ "ofb", 0 };
	block_mode_stat_map[block_mode::PCBC] = (block_mode_stat){ "pcbc", 0 };

	block_mode_name_map["cbc"] = block_mode::CBC;
	block_mode_name_map["cbc-cts"] = block_mode::CBC_CTS;
	block_mode_name_map["cts"] = block_mode::CBC_CTS;
	block_mode_name_map["cfb"] = block_mode::CFB;
	block_mode_name_map["ctr"] = block_mode::CTR;
	block_mode_name_map["ecb"] = block_mode::ECB;
	block_mode_name_map["ofb"] = block_mode::OFB;
	block_mode_name_map["pcbc"] = block_mode::PCBC;

	iv_mode_stat_map[iv_mode::ESSIV] = (iv_mode_stat){ "essiv", 1 };
	iv_mode_stat_map[iv_mode::PLAIN] = (iv_mode_stat){ "plain", 1 };

	iv_mode_name_map["essiv"] = iv_mode::ESSIV;
	iv_mode_name_map["plain"] = iv_mode::PLAIN;
}

} // end anon namespace
}

fluks::block_mode
fluks::block_mode_info::type(const std::string &name) {
	return Lookup::instance()->block_mode_lookup(name);
}

std::vector<fluks::block_mode>
fluks::block_mode_info::types() {
	std::vector<block_mode> res;
	Lookup::instance()->block_mode_types(res);
	return res;
}

const std::string &
fluks::block_mode_info::name(block_mode mode) {
	struct block_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->kern_name : blank;
}

uint16_t
fluks::block_mode_info::version(block_mode mode) {
	struct block_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->version : 0;
}

fluks::iv_mode
fluks::iv_mode_info::type(const std::string &name) {
	return Lookup::instance()->iv_mode_lookup(name);
}

std::vector<fluks::iv_mode>
fluks::iv_mode_info::types() {
	std::vector<iv_mode> res;
	Lookup::instance()->iv_mode_types(res);
	return res;
}

const std::string &
fluks::iv_mode_info::name(iv_mode mode) {
	struct iv_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->kern_name : blank;
}

uint16_t
fluks::iv_mode_info::version(iv_mode mode) {
	struct iv_mode_stat *st = Lookup::instance()->stat_lookup(mode);
	return st ? st->version : 0;
}
