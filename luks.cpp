#include <algorithm>
#include <cassert>
#include <iostream>
#include <sstream>
#include <string>
#include <boost/regex.hpp>

#include <openssl/rand.h>

#include "af.hpp"
#include "cipher.hpp"
#include "detect.hpp"
#include "hash.hpp"
#include "luks.hpp"
#include "pbkdf2.hpp"
#include "os.hpp"

namespace luks {
namespace {

std::string	make_mode(const std::string &, const std::string &,
		    const std::string &);
bool		parse_cipher(const std::string &, std::string &,
		    std::string &, std::string &, std::string &);

// reconstruct the mode string (e.g. 'cbc', 'cbc-essiv', 'cbc-essiv:sha256')
std::string
make_mode(const std::string &chainmode, const std::string &ivopts,
    const std::string &ivmode)
{
	std::ostringstream out;
	if (chainmode.size()) {
		out << chainmode;
		if (ivopts.size()) {
			out << '-' << ivopts;
			if (ivmode.size())
				out << ':' << ivmode;
		}
	}
	return out.str();
}


bool
parse_cipher(const std::string &cipher_spec, std::string &cipher,
	    std::string &chainmode, std::string &ivopts, std::string &ivmode)
{
	// valid patterns:
	// [^-]*
	// [^-]* - [^-*]
	// [^-]* - [^-*] - [^:]*
	// [^-]* - [^-*] - [^:]* : .*
	boost::regex expr(
	    "([^-]+)  (?: - ([^-]+) )?  (?: - ([^:]+) )?  (?: : (.+) )?",
	    boost::regex_constants::normal |
	    boost::regex_constants::mod_x); // ignore space

	boost::smatch matches;
	if (!boost::regex_match(cipher_spec, matches, expr))
		return false;

	cipher = matches[0];
	chainmode = matches[1];
	ivopts = matches[2];
	ivmode = matches[3];
	return true;
}

} // end anon namespace
}

luks::Luks_header::Luks_header(const std::string &device, uint32_t sz_key,
    const std::string &cipher_spec, const std::string &hash_spec,
    uint32_t mk_iterations, uint32_t stripes)
	throw (Bad_spec, Unix_error) :
	_hdr(new struct phdr1),
	_master_key(new uint8_t[sz_key]),
	_hash_type(get_hash_type(hash_spec)),
	_key_mach_end(NUM_KEYS, true),
	_hdr_mach_end(true)
{
	std::string cipher;
	std::string chainmode;
	std::string ivopts;
	std::string ivmode;

	// first split the cipher spec
	if (!parse_cipher(cipher_spec, cipher, chainmode, ivopts, ivmode))
		throw Bad_spec("unrecognized spec format");

	// make the cipher/hash specs malleable
	_cipher_type = get_cipher_type(cipher);
	_block_mode = get_block_mode(chainmode);
	_iv_opts = get_iv_opts(ivopts);
	_iv_hash = get_hash_type(ivmode);

	// are the specs supported by fluks?
	if (_cipher_type == CT_UNDEFINED)
		throw Bad_spec("unrecognized cipher");
	if (chainmode.size() && _block_mode == BM_UNDEFINED)
		throw Bad_spec("unrecognized chain mode");
	if (ivopts.size() &&  _iv_opts == IO_UNDEFINED)
		throw Bad_spec("unrecognized IV opts");
	if (ivmode.size() && _iv_hash == HT_UNDEFINED)
		throw Bad_spec("unrecognized IV mode");

	// canonize cipher and IV hash; note that ivmode will remain an
	// empty string if it was empty initially
	cipher = cipher_name(_cipher_type);
	ivmode = hash_name(_iv_hash);

	// is the cipher spec supported by the system?
	{
		const std::set<std::string> &sys_ciph = system_ciphers();
		if (!sys_ciph.count(cipher))
			throw Bad_spec("cipher not supported by system");

		const std::set<std::string> &sys_hash = system_hashes();
		if (ivmode.size() && !sys_hash.count(ivmode))
			throw Bad_spec("IV mode not supported by system");
	}

	// XXX how to check for CBC, etc?  They get added to /proc/crypto, but
	// XXX only *after* fluks attempts to use them.

	// are the specs compatible?
	if (_iv_opts == IO_ESSIV && _iv_hash == HT_UNDEFINED)
		throw Bad_spec("IV opts `essiv' requires an IV mode");
	if (_iv_opts == IO_PLAIN && _iv_hash != HT_UNDEFINED)
		throw Bad_spec("IV opts `plain' cannot use an IV mode");
	if (_iv_opts == IO_ESSIV) {
		// check that ESSIV hash size is a possible key size of the
		// cipher
		std::vector<uint16_t> sizes = cipher_key_sizes(_cipher_type);
		uint16_t size = hash_digest_size(_iv_hash);
		if (std::find(sizes.begin(), sizes.end(), size) !=
		    sizes.end()) {
			typedef std::vector<uint16_t>::iterator Iter;
			std::ostringstream out;
			out << "cipher `" << cipher
			    << "' only supports keys of sizes";
			for (Iter i = sizes.begin(); i != sizes.end(); ++i) {
				if (i != sizes.begin())
					out << ',';
				out << ' ' << *i;
			}
			throw Bad_spec(out.str());
		}
	}

	// initialize LUKS header

	if (!RAND_bytes(_master_key.get(), _hdr->sz_key))
		throw Ssl_error();

	std::copy(MAGIC, MAGIC + sizeof(MAGIC),_hdr->magic);
	_hdr->version = 1;

	// recreate a canonical cipher spec, canonize the hash spec; note
	// that cipher and ivmode were already changed
	std::string mode = make_mode(chainmode, ivopts, ivmode);
	std::string hash = hash_name(_hash_type);

	// copy specs into header
	std::copy(cipher.begin(), cipher.end(), _hdr->cipher_name);
	std::copy(mode.begin(), mode.end(), _hdr->block_mode);
	std::copy(hash_spec.begin(), hash_spec.end(), _hdr->hash_spec);

	_hdr->sz_key = sz_key;
	if (!RAND_bytes(_hdr->mk_salt, SZ_SALT))
		throw Ssl_error();
	_hdr->mk_iterations = mk_iterations;

	// hash the master key
	pbkdf2(_hash_type, _master_key.get(), sz_key, _hdr->mk_salt,
	    _hdr->mk_iterations, _hdr->mk_digest, SZ_MK_DIGEST);

	int sz_sector = sector_size(device);
	// LUKS defines off_base as
	//	floor(sizeof(phdr) / sz_sector) + 1,
	// but it is clearly more correct to use
	//	ceil(sizeof(phdr) / sz_sector).
	// the same goes for km_sectors
	uint32_t off_base = (sizeof(phdr1) + sz_sector - 1) / sz_sector;
	uint32_t km_sectors =
	    (stripes * _hdr->sz_key + sz_sector - 1) / sz_sector;

	for (size_t i = 0; i < NUM_KEYS; i++) {
		_hdr->keys[i].active = KEY_DISABLED;
		_hdr->keys[i].stripes = stripes;
		_hdr->keys[i].off_km = off_base;

		off_base += km_sectors;
	}

	_hdr->off_payload = off_base;
	//TODO hdr->uuid = generate_uuid()
}

luks::Luks_header::Luks_header(const std::string &device)
{
	// TODO
	throw std::exception();
}

bool
luks::Luks_header::read_key(const std::string &passwd, int8_t hint)
{
	uint8_t pw_digest[_hdr->sz_key];
	uint8_t key_merged[_hdr->sz_key];
	uint8_t key_digest[hash_digest_size(_hash_type)];
	struct key *key;

	if (_master_key)
		return false;
	ensure_mach_hdr(true);

	size_t i;
	size_t max;
	if (hint < 0) {
		i = hint;
		max = hint + 1;
	} else {
		i = 0;
		max = NUM_KEYS;
	}

	for (; i < max; i++) {
		ensure_mach_key(i, true);
		key = _hdr->keys + i;

		uint8_t key_crypt[_hdr->sz_key * key->stripes];
		uint8_t key_splitted[sizeof(key_crypt)];

		// password => pw_digest
		pbkdf2(_hash_type,
		    reinterpret_cast<const uint8_t *>(passwd.c_str()),
		    passwd.size(), key->salt, key->iterations, pw_digest,
		    sizeof(pw_digest));

		// disk => key_crypt
		// TODO key_crypt = read(key->off_km, sizeof(pw_disk_crypt));

		// (pw_digest, key_crypt) => key_splitted
		// TODO key_splitted = decrypt(_hdr->cipher_name,
		//	_hdr->cipher_mode, pw_digest, key_crypt,
		//	sizeof(key_crypt));

		// key_splitted => key_merged
		af_merge(key_splitted, sizeof(key_splitted), key->stripes,
		    _hash_type, key_merged);

		// key_merged => key_digest
		pbkdf2(_hash_type, key_merged, sizeof(key_merged),
		    _hdr->mk_salt, _hdr->mk_iterations, key_digest,
		    SZ_MK_DIGEST);

		if (std::equal(pw_digest, key_digest + sizeof(key_digest),
		    _hdr->mk_digest)) {
			_master_key.reset(new uint8_t[_hdr->sz_key]);
			std::copy(key_merged, key_merged + sizeof(key_merged),
			    _master_key.get());
			return true;
		}
	}
	return false;
}

void
luks::Luks_header::add_passwd(const std::string &passwd, uint32_t check_time)
	throw (Slots_full)
{
	struct key *avail = 0;

	assert(_master_key);
	ensure_mach_hdr(true);

	// find an open slot
	for (size_t i = 0; i < NUM_KEYS; i++) {
		ensure_mach_key(i, true);
		if (_hdr->keys[i].active == KEY_DISABLED) {
			avail = _hdr->keys + i;
			break;
		}
	}
	if (!avail) throw Slots_full();

	uint8_t split_key[_hdr->sz_key * avail->stripes];

	if (!RAND_bytes(avail->salt, SZ_SALT))
		throw Ssl_error();
	af_split(_master_key.get(), _hdr->sz_key, avail->stripes,
	    _hash_type, split_key);

	uint8_t pw_digest[_hdr->sz_key];

	// benchmark the PBKDF2 function
	const uint32_t ITER = 100000;
	uint32_t micros = pbkdf2(_hash_type,
	    reinterpret_cast<const uint8_t *>(passwd.c_str()),
	    passwd.size(), avail->salt, ITER, pw_digest,
	    sizeof(pw_digest), true);

	avail->iterations = static_cast<uint32_t>(
	    static_cast<uint64_t>(ITER) * check_time / micros);

	// compute digest for realsies
	pbkdf2(_hash_type,
	    reinterpret_cast<const uint8_t *>(passwd.c_str()),
	    passwd.size(), avail->salt, avail->iterations, pw_digest,
	    sizeof(pw_digest));

	uint8_t pw_crypt[sizeof(split_key)];
	// TODO pw_crypt = encrypt(_hdr->cipher_name, _hdr->cipher_mode,
	//	pw_digest, split_key, sizeof(split_key));

	avail->active = KEY_ENABLED;
}

void
luks::Luks_header::revoke_slot(uint8_t which)
{
	ensure_mach_key(which, true);
	_hdr->keys[which].active = KEY_DISABLED;
	// see http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html
	// TODO gutmann_erase(key->off_km, hdr->sz_key * key->stripes);
}


enum luks::block_mode
luks::get_block_mode(const std::string &mode)
{
	if (mode == "cbc") return BM_CBC;
	if (mode == "ctr") return BM_CTR;
	if (mode == "cts") return BM_CTS;
	if (mode == "pcbc") return BM_PCBC;
	return BM_UNDEFINED;
}

enum luks::iv_opts
luks::get_iv_opts(const std::string &ivopts)
{
	if (ivopts == "plain") return IO_PLAIN;
	if (ivopts == "essiv") return IO_ESSIV;
	return IO_UNDEFINED;
}
