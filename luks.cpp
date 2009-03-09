#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <boost/regex.hpp>

#include <openssl/rand.h>

#include <uuid/uuid.h>

#include "af.hpp"
#include "cipher.hpp"
#include "crypt.hpp"
#include "detect.hpp"
#include "gutmann.hpp"
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
make_mode(const std::string &block_mode, const std::string &ivmode,
    const std::string &ivhash)
{
	std::ostringstream out;
	if (block_mode.size()) {
		out << block_mode;
		if (ivmode.size()) {
			out << '-' << ivmode;
			if (ivhash.size())
				out << ':' << ivhash;
		}
	}
	return out.str();
}


bool
parse_cipher(const std::string &cipher_spec, std::string &cipher,
	    std::string &block_mode, std::string &ivmode, std::string &ivhash)
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

	cipher = matches[1];
	block_mode = matches[2];
	ivmode = matches[3];
	ivhash = matches[4];
	return true;
}

} // end anon namespace
}

bool
luks::header_version_1(const struct phdr1 *header)
{
	if (!std::equal(MAGIC, MAGIC + sizeof(MAGIC), header->magic))
		return false;
	return header->version == 1;
}

luks::Luks_header::Luks_header(const std::string &device, uint32_t sz_key,
    const std::string &cipher_spec, const std::string &hash_spec,
    uint32_t mk_iterations, uint32_t stripes)
    throw (Bad_spec, Unix_error) :
	_device(device),
	_hdr(new struct phdr1),
	_master_key(new uint8_t[sz_key]),
	_sz_sect(sector_size(device)),
	_hash_type(get_hash_type(hash_spec)),
	_key_mach_end(NUM_KEYS, true),
	_hdr_mach_end(true),
	_key_dirty(NUM_KEYS, true),
	_hdr_dirty(true),
	_key_need_erase(NUM_KEYS, false)
{
	init_cipher_spec(cipher_spec);
	if (_hash_type == HT_UNDEFINED)
		throw Bad_spec("unrecognized hash");

	// initialize LUKS header

	if (!RAND_bytes(_master_key.get(), _hdr->sz_key))
		throw Ssl_error();

	std::copy(MAGIC, MAGIC + sizeof(MAGIC),_hdr->magic);
	_hdr->version = 1;

	std::copy(hash_spec.begin(), hash_spec.end(), _hdr->hash_spec);

	_hdr->sz_key = sz_key;
	if (!RAND_bytes(_hdr->mk_salt, SZ_SALT))
		throw Ssl_error();
	_hdr->mk_iterations = mk_iterations;

	// hash the master key
	pbkdf2(_hash_type, _master_key.get(), sz_key, _hdr->mk_salt,
	    _hdr->mk_iterations, _hdr->mk_digest, SZ_MK_DIGEST);

	// LUKS defines off_base as
	//	floor(sizeof(phdr) / sz_sect) + 1,
	// but it is clearly more correct to use
	//	ceil(sizeof(phdr) / sz_sect).
	// the same goes for km_sectors
	uint32_t off_base = (sizeof(phdr1) + _sz_sect - 1) / _sz_sect;
	uint32_t km_sectors =
	    (stripes * _hdr->sz_key + _sz_sect - 1) / _sz_sect;

	for (size_t i = 0; i < NUM_KEYS; i++) {
		_hdr->keys[i].active = KEY_DISABLED;
		_hdr->keys[i].stripes = stripes;
		_hdr->keys[i].off_km = off_base;

		off_base += km_sectors;
	}

	_hdr->off_payload = off_base;

	uuid_t uuid; // actually a buffer
	uuid_generate(uuid);
	uuid_unparse(uuid, _hdr->uuid_part);
}

luks::Luks_header::Luks_header(const std::string &device)
    throw (Bad_spec, Disk_error, Unix_error, Unsupported_version) :
	_device(device),
	_hdr(new struct phdr1),
	_sz_sect(sector_size(device)),
	_key_mach_end(NUM_KEYS, false),
	_hdr_mach_end(false),
	_key_dirty(NUM_KEYS, false),
	_hdr_dirty(false),
	_key_need_erase(NUM_KEYS, false)
{
	std::ifstream dev_in(_device.c_str(),
	    std::ios_base::binary | std::ios_base::in);
	if (!dev_in)
		throw Disk_error("failed to open device");

	dev_in.read(reinterpret_cast<char *>(_hdr.get()),
	    sizeof(struct phdr1));
	if (!dev_in)
		throw Disk_error("failed to read header");

	// big-endian -> machine-endian
	ensure_mach_hdr(true);

	if (!header_version_1(_hdr.get()))
		throw Unsupported_version();

	{
		// recreate the cipher-spec string
		std::string cipher_spec = _hdr->cipher_name;
		if (*_hdr->cipher_mode) {
			cipher_spec += '-';
			cipher_spec += _hdr->cipher_mode;
		}
		init_cipher_spec(cipher_spec);
	}

	_hash_type = get_hash_type(_hdr->hash_spec);

	if (_hash_type == HT_UNDEFINED)
		throw Bad_spec(
		    std::string("undefined hash spec in header: ") +
		    _hdr->hash_spec);
}

bool
luks::Luks_header::read_key(const std::string &passwd, int8_t hint)
    throw (Disk_error)
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

	std::ifstream dev_in(_device.c_str(), 
	    std::ios_base::binary | std::ios_base::in);
	if (!dev_in)
		throw Disk_error("failed to open device");

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
		dev_in.seekg(key->off_km * _sz_sect, std::ios_base::beg);
		if (!dev_in)
			throw Disk_error("failed to seek to key material");

		dev_in.read(reinterpret_cast<char *>(key_crypt),
		    sizeof(key_crypt));
		if (!dev_in)
			throw Disk_error("failed to read key material");

		// (pw_digest, key_crypt) => key_splitted
		decrypt(_cipher_type, _block_mode, _iv_mode, _iv_hash,
		    key->off_km, _sz_sect,
		    pw_digest, sizeof(pw_digest),
		    key_crypt, sizeof(key_crypt),
		    key_splitted);

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
    throw (No_private_key, Slots_full)
{
	struct key *avail = 0;
	size_t avail_idx = 0;

	if (!_master_key) throw No_private_key();

	ensure_mach_hdr(true);

	// find an open slot
	for (size_t i = 0; i < NUM_KEYS; i++) {
		ensure_mach_key(i, true);
		if (_hdr->keys[i].active == KEY_DISABLED) {
			avail = _hdr->keys + i;
			avail_idx = i;
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

	// encrypt the master key with pw_digest
	_key_crypt[avail_idx].reset(new uint8_t[sizeof(split_key)]);
	encrypt(_cipher_type, _block_mode, _iv_mode, _iv_hash,
	    avail->off_km, _sz_sect,
	    pw_digest, sizeof(pw_digest),
	    _master_key.get(), _hdr->sz_key,
	    _key_crypt[avail_idx].get());

	avail->active = KEY_ENABLED;
	_hdr_dirty = true;
	_key_dirty[avail_idx] = true;
}

void
luks::Luks_header::revoke_slot(uint8_t which)
{
	ensure_mach_key(which, true);
	_hdr->keys[which].active = KEY_DISABLED;
	_hdr_dirty = true;
	_key_dirty[which] = true;
	_key_need_erase[which] = true;
}

void
luks::Luks_header::save() throw (Disk_error)
{
	if (!_hdr_dirty) return;

	std::ofstream dev_out(_device.c_str(),
	    std::ios_base::binary | std::ios_base::in);
	if (!dev_out)
		throw Disk_error("failed to open device");

	// first erase old keys and then commit new keys
	for (uint8_t i = 0; i < NUM_KEYS; i++) {
		if (_key_dirty[i]) {
			ensure_mach_key(i, true);
			if (_key_need_erase[i]) {
				gutmann_erase(dev_out,
				    _hdr->keys[i].off_km * _sz_sect,
				    _hdr->sz_key * _hdr->keys[i].stripes);
				_key_need_erase[i] = false;
			}
			if (_hdr->keys[i].active == KEY_ENABLED) {
				dev_out.seekp(_hdr->keys[i].off_km * _sz_sect,
				    std::ios_base::beg);
				if (!dev_out)
					throw Disk_error("writing key "
					    "material: seek error");

				dev_out.write(reinterpret_cast<char *>(
				    _key_crypt[i].get()),
				    _hdr->keys[i].off_km * _sz_sect);
				if (!dev_out)
					throw Disk_error("writing key "
					    "material: write error");
				_key_crypt[i].reset();
			}
		}
		// ensure big-endian
		ensure_mach_key(i, false);
	}

	if (_hdr_dirty) {
		// ensure big-endian
		ensure_mach_hdr(false);

		dev_out.seekp(0, std::ios_base::beg);
		if (!dev_out)
			throw Disk_error("writing header: seek error");

		dev_out.write(reinterpret_cast<char *>(_hdr.get()),
		    sizeof(_hdr));
		if (!dev_out)
			throw Disk_error("writing header: write error");

		_hdr_dirty = false;
	}
}

// initializes the values of the cipher-spec enums and the cipher-spec
// strings in the LUKS header, throwing Bad_spec as necessary
void
luks::Luks_header::init_cipher_spec(const std::string &cipher_spec)
{
	std::string cipher;
	std::string block_mode;
	std::string ivmode;
	std::string ivhash;

	// first split the cipher spec
	if (!parse_cipher(cipher_spec, cipher, block_mode, ivmode, ivhash))
		throw Bad_spec("unrecognized spec format");

	// make the cipher/hash specs malleable
	_cipher_type = get_cipher_type(cipher);
	_block_mode = get_block_mode(block_mode);
	_iv_mode = get_iv_mode(ivmode);
	_iv_hash = get_hash_type(ivhash);

	// are the specs supported by fluks?
	if (_cipher_type == CT_UNDEFINED)
		throw Bad_spec("unrecognized cipher: " + cipher);
	if (block_mode.size() && _block_mode == BM_UNDEFINED)
		throw Bad_spec("unrecognized block mode: " + block_mode);
	if (ivmode.size() &&  _iv_mode == IM_UNDEFINED)
		throw Bad_spec("unrecognized IV mode: " + ivmode);
	if (ivhash.size() && _iv_hash == HT_UNDEFINED)
		throw Bad_spec("unrecognized IV hash: " + ivhash);

	// canonize cipher and IV hash; note that ivhash will remain an
	// empty string if it was empty initially
	cipher = cipher_name(_cipher_type);
	ivhash = hash_name(_iv_hash);

	// is the cipher spec supported by the system?
	{
		const std::set<std::string> &sys_ciph = system_ciphers();
		if (!sys_ciph.count(cipher))
			throw Bad_spec("cipher not supported by system: " +
			    cipher);

		const std::set<std::string> &sys_hash = system_hashes();
		if (ivhash.size() && !sys_hash.count(ivhash))
			throw Bad_spec("IV hash not supported by system: " +
			    ivhash);
	}

	// XXX how to check for CBC, etc?  They get added to /proc/crypto, but
	// XXX only *after* dm-crypt attempts to use them.

	// are the specs compatible?
	if (_block_mode == BM_ECB && _iv_mode != IM_UNDEFINED)
		throw Bad_spec("ECB mode cannot have an IV mode parameter");
	if (_iv_mode == IM_ESSIV && _iv_hash == HT_UNDEFINED)
		throw Bad_spec("IV mode `essiv' requires an IV hash");
	if (_iv_mode == IM_PLAIN && _iv_hash != HT_UNDEFINED)
		throw Bad_spec("IV mode `plain' cannot use an IV hash");
	if (_iv_mode == IM_ESSIV) {
		// check that ESSIV hash size is a possible key size of the
		// cipher
		std::vector<uint16_t> sizes = cipher_key_sizes(_cipher_type);
		uint16_t size = hash_digest_size(_iv_hash);
		if (std::find(sizes.begin(), sizes.end(), size) ==
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
			out << "; incompatible with hash `" << ivhash << '\'';
			throw Bad_spec(out.str());
		}
	}

	// recreate a canonical cipher spec, canonize the hash spec; note
	// that cipher and ivhash were already canonized
	std::string mode = make_mode(block_mode, ivmode, ivhash);
	std::string hash = hash_name(_hash_type);

	// copy specs into header
	std::copy(cipher.begin(), cipher.end(), _hdr->cipher_name);
	std::copy(mode.begin(), mode.end(), _hdr->cipher_mode);
}


enum luks::block_mode
luks::get_block_mode(const std::string &mode)
{
	if (mode == "cbc") return BM_CBC;
	if (mode == "ctr") return BM_CTR;
	if (mode == "ecb") return BM_ECB;
	if (mode == "pcbc") return BM_PCBC;
	return BM_UNDEFINED;
}

enum luks::iv_mode
luks::get_iv_mode(const std::string &name)
{
	if (name == "plain") return IM_PLAIN;
	if (name == "essiv") return IM_ESSIV;
	return IM_UNDEFINED;
}

