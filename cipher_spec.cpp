/* Copyright (c) 2009-2010, Markus Peloquin <markus@cs.wisc.edu>
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

#include <regex>
#include <set>
#include <sstream>

#include "cipher.hpp"
#include "cipher_spec.hpp"
#include "detect.hpp"
#include "hash.hpp"
#include "support.hpp"

namespace fluks {
namespace {
} // end anon
}

void
fluks::Cipher_spec::check_spec_support(const Cipher_traits *cipher_traits,
    const Hash_traits *hash_traits) noexcept(false) {
	// is the cipher spec supported by the system?
	const std::set<std::string> &sys_ciph = system_ciphers();
	if (!sys_ciph.count(cipher_traits->name))
		throw Bad_spec("cipher not supported by system: " +
		    _nm_cipher);

	const std::set<std::string> &sys_hash = system_hashes();
	if (_nm_iv_hash.size() && !sys_hash.count(hash_traits->name))
		throw Bad_spec("IV hash not supported by system: " +
		    _nm_iv_hash);
}

void
fluks::Cipher_spec::check_spec(ssize_t sz_key) noexcept(false) {
	if (_ty_cipher == cipher_type::UNDEFINED)
		throw Bad_spec("unrecognized cipher: " + _nm_cipher);
	if (_ty_block_mode == block_mode::UNDEFINED)
		throw Bad_spec("unrecognized block mode: " +
		    _nm_block_mode);
	if (!_nm_iv_mode.empty() && _ty_iv_mode == iv_mode::UNDEFINED)
		throw Bad_spec("unrecognized IV mode: " + _nm_iv_mode);
	if (!_nm_iv_hash.empty() && _ty_iv_hash == hash_type::UNDEFINED)
		throw Bad_spec("unrecognized IV hash: " + _nm_iv_hash);

	const Cipher_traits *cipher_traits =
	    Cipher_traits::traits(_ty_cipher);
	const Hash_traits *ivhash_traits =
	    Hash_traits::traits(_ty_iv_hash);

	check_spec_support(cipher_traits, ivhash_traits);

	// XXX how to check for CBC, etc?  They get added to /proc/crypto, but
	// XXX only *after* dm-crypt attempts to use them.

	const std::vector<uint16_t> &sizes = cipher_traits->key_sizes;
	if (sz_key != -1 &&
	    !std::binary_search(sizes.begin(), sizes.end(), sz_key)) {
		// sz_key not compatible with the cipher
		std::ostringstream out;
		out << "cipher `" << _nm_cipher
		    << "' only supports keys of sizes";
		bool first = true;
		for (uint16_t size : sizes) {
			if (!first) out << ',';
			first = false;
			out << ' ' << size * 8;
		}
		out << " (not " << sz_key << ')';
		throw Bad_spec(out.str());
	}

	// are the specs compatible?
	if (_ty_block_mode == block_mode::ECB &&
	    _ty_iv_mode != iv_mode::UNDEFINED)
		throw Bad_spec("ECB cannot use an IV mode");
	if (_ty_block_mode != block_mode::ECB &&
	    _ty_iv_mode == iv_mode::UNDEFINED)
		throw Bad_spec(
		    "block modes other than ECB require an IV mode");
	if (_ty_iv_mode == iv_mode::ESSIV &&
	    _ty_iv_hash == hash_type::UNDEFINED)
		throw Bad_spec("IV mode `essiv' requires an IV hash");
	if (_ty_iv_mode == iv_mode::PLAIN &&
	    _ty_iv_hash != hash_type::UNDEFINED)
		throw Bad_spec("IV mode `plain' cannot use an IV hash");
	if (_ty_iv_mode == iv_mode::ESSIV) {
		// check that ESSIV hash size is a possible key size of the
		// cipher
		uint16_t size = ivhash_traits->digest_size;
		if (!std::binary_search(sizes.begin(), sizes.end(), size)) {
			std::ostringstream out;
			out << "cipher `" << _nm_cipher
			    << "' only supports keys of sizes";
			bool first = true;
			for (uint16_t size : sizes) {
				if (!first) out << ',';
				first = false;
				out << ' ' << size * 8;
			}
			out << "; incompatible with hash `" << _nm_iv_hash
			    << '\'';
			throw Bad_spec(out.str());
		}
	}
}

void
fluks::Cipher_spec::reset(ssize_t sz_key, const std::string &spec)
    noexcept(false) {
	// valid patterns:
	// [^-]* - [^-*]
	// [^-]* - [^-*] - [^:]*
	// [^-]* - [^-*] - [^:]* : .*
	std::regex expr(
	    "([^-]+)-([^-]+)(?:-([^:]+))?(?::(.+))?");

	std::smatch matches;
	if (!std::regex_match(spec, matches, expr))
		throw Bad_spec("cannot be parsed");

	_nm_cipher = matches[1];
	_nm_block_mode = matches[2];
	_nm_iv_mode = matches[3];
	_nm_iv_hash = matches[4];

	_ty_cipher = Cipher_traits::type(_nm_cipher);
	_ty_block_mode = block_mode_info::type(_nm_block_mode);
	_ty_iv_mode = iv_mode_info::type(_nm_iv_mode);
	_ty_iv_hash = Hash_traits::type(_nm_iv_hash);

	check_spec(sz_key);
}

void
fluks::Cipher_spec::reset(ssize_t sz_key, cipher_type cipher,
    block_mode block_mode, iv_mode iv_mode, hash_type iv_hash)
    noexcept(false) {
	const Cipher_traits *ctraits = Cipher_traits::traits(_ty_cipher);
	_nm_cipher = ctraits->name;
	_nm_block_mode = block_mode_info::name(_ty_block_mode);
	_nm_iv_mode = iv_mode_info::name(_ty_iv_mode);
	const Hash_traits *htraits = Hash_traits::traits(_ty_iv_hash);
	_nm_iv_hash = htraits->name;

	check_spec(sz_key);
}

std::string
fluks::Cipher_spec::canon_cipher() const {
	const Cipher_traits *traits = Cipher_traits::traits(_ty_cipher);
	return traits->name;
}

std::string
fluks::Cipher_spec::canon_mode() const {
	std::string result = block_mode_info::name(_ty_block_mode);
	if (_ty_iv_mode != iv_mode::UNDEFINED) {
		result += '-';
		result += iv_mode_info::name(_ty_iv_mode);
	}
	if (_ty_iv_hash != hash_type::UNDEFINED) {
		const Hash_traits *traits = Hash_traits::traits(_ty_iv_hash);
		result += ':';
		result += traits->name;
	}
	return result;
}
