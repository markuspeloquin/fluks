#include <set>
#include <sstream>
#include <boost/regex.hpp>

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
    const Hash_traits *hash_traits) throw (Bad_spec)
{
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
fluks::Cipher_spec::check_spec(ssize_t sz_key) throw (Bad_spec)
{
	if (_ty_cipher == CT_UNDEFINED)
		throw Bad_spec("unrecognized cipher: " + _nm_cipher);
	if (_ty_block_mode == BM_UNDEFINED)
		throw Bad_spec("unrecognized block mode: " +
		    _nm_block_mode);
	if (!_nm_iv_mode.empty() && _ty_iv_mode == IM_UNDEFINED)
		throw Bad_spec("unrecognized IV mode: " + _nm_iv_mode);
	if (!_nm_iv_hash.empty() && _ty_iv_hash == HT_UNDEFINED)
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
		for (std::vector<uint16_t>::const_iterator i = sizes.begin();
		    i != sizes.end(); ++i) {
			if (i != sizes.begin()) out << ',';
			out << ' ' << *i * 8;
		}
		out << " (not " << sz_key << ')';
		throw Bad_spec(out.str());
	}

	// are the specs compatible?
	if (_ty_block_mode == BM_ECB && _ty_iv_mode != IM_UNDEFINED)
		throw Bad_spec("ECB cannot use an IV mode");
	if (_ty_block_mode != BM_ECB && _ty_iv_mode == IM_UNDEFINED)
		throw Bad_spec(
		    "block modes other than ECB require an IV mode");
	if (_ty_iv_mode == IM_ESSIV && _ty_iv_hash == HT_UNDEFINED)
		throw Bad_spec("IV mode `essiv' requires an IV hash");
	if (_ty_iv_mode == IM_PLAIN && _ty_iv_hash != HT_UNDEFINED)
		throw Bad_spec("IV mode `plain' cannot use an IV hash");
	if (_ty_iv_mode == IM_ESSIV) {
		// check that ESSIV hash size is a possible key size of the
		// cipher
		uint16_t size = ivhash_traits->digest_size;
		if (!std::binary_search(sizes.begin(), sizes.end(), size)) {
			std::ostringstream out;
			out << "cipher `" << _nm_cipher
			    << "' only supports keys of sizes";
			for (std::vector<uint16_t>::const_iterator i =
			    sizes.begin(); i != sizes.end(); ++i) {
				if (i != sizes.begin())
					out << ',';
				out << ' ' << (*i * 8);
			}
			out << "; incompatible with hash `" << _nm_iv_hash
			    << '\'';
			throw Bad_spec(out.str());
		}
	}
}

void
fluks::Cipher_spec::reset(ssize_t sz_key, const std::string &spec)
    throw (Bad_spec)
{
	// valid patterns:
	// [^-]* - [^-*]
	// [^-]* - [^-*] - [^:]*
	// [^-]* - [^-*] - [^:]* : .*
	boost::regex expr(
	    "([^-]+) - ([^-]+)  (?: - ([^:]+) )?  (?: : (.+) )?",
	    boost::regex_constants::normal |
	    boost::regex_constants::mod_x); // ignore space

	boost::smatch matches;
	if (!boost::regex_match(spec, matches, expr))
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
fluks::Cipher_spec::reset(ssize_t sz_key, enum cipher_type cipher,
    enum block_mode block_mode, enum iv_mode iv_mode, enum hash_type iv_hash)
    throw (Bad_spec)
{
	const Cipher_traits *ctraits = Cipher_traits::traits(_ty_cipher);
	_nm_cipher = ctraits->name;
	_nm_block_mode = block_mode_info::name(_ty_block_mode);
	_nm_iv_mode = iv_mode_info::name(_ty_iv_mode);
	const Hash_traits *htraits = Hash_traits::traits(_ty_iv_hash);
	_nm_iv_hash = htraits->name;

	check_spec(sz_key);
}

std::string
fluks::Cipher_spec::canon_cipher() const
{
	const Cipher_traits *traits = Cipher_traits::traits(_ty_cipher);
	return traits->name;
}

std::string
fluks::Cipher_spec::canon_mode() const
{
	std::string result = block_mode_info::name(_ty_block_mode);
	if (_ty_iv_mode) {
		result += '-';
		result += iv_mode_info::name(_ty_iv_mode);
	}
	if (_ty_iv_hash) {
		const Hash_traits *traits = Hash_traits::traits(_ty_iv_hash);
		result += ':';
		result += traits->name;
	}
	return result;
}
