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

#include "cipher.hpp"

namespace fluks {
namespace {

class Lookup {
public:
	static const Cipher_traits *traits(cipher_type type);
	static cipher_type type(const std::string &name);

	static const std::vector<cipher_type> &types() {
		return inst._types;
	}

private:
	Lookup();
	Lookup(const Lookup &) {}
	void operator=(const Lookup &) {}

	static Lookup inst;
	std::map<cipher_type, Cipher_traits> _map_traits;
	std::map<std::string, cipher_type> _map_type;
	std::vector<cipher_type> _types;
};

const Cipher_traits *
Lookup::traits(cipher_type type) {
	auto i = inst._map_traits.find(type);
	if (i == inst._map_traits.end()) return 0;
	return &i->second;
}

cipher_type
Lookup::type(const std::string &name) {
	auto i = inst._map_type.find(name);
	if (i == inst._map_type.end()) return cipher_type::UNDEFINED;
	return i->second;
}

Lookup::Lookup() {
	// name, min_key, max_key, key_step, blocksize, version
	_map_traits[cipher_type::AES] = Cipher_traits("aes", 16, 32, 8, 16, 1);
	_map_traits[cipher_type::BLOWFISH] = Cipher_traits("blowfish", 4, 56, 1, 8, 0);
#ifndef OPENSSL_NO_CAMELLIA
	_map_traits[cipher_type::CAMELLIA] = Cipher_traits("camellia", 16, 32, 8, 16, 0);
#endif
	_map_traits[cipher_type::CAST5] = Cipher_traits("cast5", 5, 16, 1, 8, 1);
	_map_traits[cipher_type::CAST6] = Cipher_traits("cast6", 16, 32, 4, 16, 1);
	_map_traits[cipher_type::SERPENT] = Cipher_traits("serpent", 16, 32, 8, 16, 1);
	_map_traits[cipher_type::TWOFISH] = Cipher_traits("twofish", 16, 32, 8, 16, 1);

	_map_type["aes"] = cipher_type::AES;
	_map_type["blowfish"] = cipher_type::BLOWFISH;
#ifndef OPENSSL_NO_CAMELLIA
	_map_type["camellia"] = cipher_type::CAMELLIA;
#endif
	_map_type["cast5"] = cipher_type::CAST5;
	_map_type["cast6"] = cipher_type::CAST6;
	_map_type["serpent"] = cipher_type::SERPENT;
	_map_type["twofish"] = cipher_type::TWOFISH;

	for (auto &pair : _map_traits)
		_types.push_back(pair.first);
}

Lookup Lookup::inst;

} // end anon namespace
}

fluks::Cipher_traits::Cipher_traits(const std::string &name,
    uint16_t min_key, uint16_t max_key, uint16_t key_step,
    uint16_t sz_blk, uint16_t version) :
	name(name),
	key_sizes((max_key - min_key + key_step) / key_step),
	block_size(sz_blk),
	luks_version(version)
{
	uint16_t i = 0;
	for (uint16_t n = min_key; n <= max_key; n += key_step)
		key_sizes[i++] = n;
}

const fluks::Cipher_traits *
fluks::Cipher_traits::traits(cipher_type type) {
	return Lookup::traits(type);
}

fluks::cipher_type
fluks::Cipher_traits::type(const std::string &name) {
	return Lookup::type(name);
}

const std::vector<fluks::cipher_type> &
fluks::Cipher_traits::types() {
	return Lookup::types();
}

std::shared_ptr<fluks::Cipher>
fluks::Cipher::create(cipher_type type) {
	switch (type) {
	case cipher_type::AES:
		return std::shared_ptr<Cipher>(new Cipher_aes);
	case cipher_type::BLOWFISH:
		return std::shared_ptr<Cipher>(new Cipher_blowfish);
#ifndef OPENSSL_NO_CAMELLIA
	case cipher_type::CAMELLIA:
		return std::shared_ptr<Cipher>(new Cipher_camellia);
#endif
	case cipher_type::CAST5:
		return std::shared_ptr<Cipher>(new Cipher_cast5);
	case cipher_type::CAST6:
		return std::shared_ptr<Cipher>(new Cipher_cast6);
	case cipher_type::SERPENT:
		return std::shared_ptr<Cipher>(new Cipher_serpent);
	case cipher_type::TWOFISH:
		return std::shared_ptr<Cipher>(new Cipher_twofish);
	default:
		Assert(0, "Cipher::create() bad cipher type");
		return std::shared_ptr<Cipher>();
	}
}
