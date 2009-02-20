#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <string>

#include <openssl/rand.h>

#include "af.hpp"
#include "hash.hpp"
#include "luks.hpp"
#include "pbkdf2.hpp"

luks::Luks_header::Luks_header(uint32_t sz_key,
    const std::string &cipher_name, const std::string &cipher_mode,
    const std::string &hash_spec, uint32_t mk_iterations, uint32_t stripes)
	throw (Bad_spec) :
	_hdr(new struct phdr1),
	_master_key(new uint8_t[sz_key]),
	_hash_type(hash_type(hash_spec)),
	_key_mach_end(NUM_KEYS, true),
	_hdr_mach_end(true)
{
	if (cipher_name.size() + 1 >= SZ_CIPHER_NAME)
		throw Bad_spec("cipher name too long");
	if (cipher_mode.size() + 1 >= SZ_CIPHER_MODE)
		throw Bad_spec("cipher mode too long");
	if (hash_spec.size() + 1 >= SZ_HASH_SPEC)
		throw Bad_spec("hash spec too long");
	if (0/* unrecognized? */)
		throw Bad_spec("you little...");

	// values set in the order in 'struct phdr1' structure

	if (!RAND_bytes(_master_key.get(), _hdr->sz_key))
		throw Ssl_error();

	memcpy(_hdr->magic, MAGIC, sizeof(MAGIC));
	_hdr->version = 1;

	memcpy(_hdr->cipher_name, cipher_name.c_str(), cipher_name.size() + 1);
	memcpy(_hdr->cipher_mode, cipher_mode.c_str(), cipher_mode.size() + 1);
	memcpy(_hdr->hash_spec, hash_spec.c_str(), cipher_mode.size() + 1);

	_hdr->sz_key = sz_key;
	if (!RAND_bytes(_hdr->mk_salt, SZ_SALT))
		throw Ssl_error();
	_hdr->mk_iterations = mk_iterations;

	// hash the master key
	pbkdf2(_hash_type, _master_key.get(), sz_key, _hdr->mk_salt,
	    _hdr->mk_iterations, _hdr->mk_digest, SZ_MK_DIGEST);

	/*TODO (totally fake) */ const uint32_t SECTOR_SIZE = 2048;
	uint32_t off_base = sizeof(phdr1) / SECTOR_SIZE + 1;
	uint32_t km_sectors = (stripes * _hdr->sz_key) / SECTOR_SIZE + 1;

	for (size_t i = 0; i < NUM_KEYS; i++) {
		_hdr->keys[i].active = KEY_DISABLED;
		_hdr->keys[i].stripes = stripes;
		_hdr->keys[i].off_km = off_base;

		off_base += km_sectors;
	}

	_hdr->off_payload = off_base;
	//TODO hdr->uuid = generate_uuid()

	//TODO write_to_disk(_hdr)
}

luks::Luks_header::Luks_header(off_t offset)
{
	// TODO
	throw std::exception();
}

bool
luks::Luks_header::read_key(const std::string &passwd, int8_t hint)
{
	uint8_t pw_digest[_hdr->sz_key];
	uint8_t key_merged[_hdr->sz_key];
	uint8_t key_digest[hash_size(_hash_type)];
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
			memcpy(_master_key.get(), key_merged,
			    sizeof(key_merged));
			return true;
		}
	}
	return false;
}

void
luks::Luks_header::add_passwd(const std::string &passwd)
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

	// TODO PBKDF2_iterations_per_second = benchmark system
	// avail.iterations = PBKDF2_iterations_per_second *
	//	intented_password_checking_time

	if (!RAND_bytes(avail->salt, SZ_SALT))
		throw Ssl_error();
	af_split(_master_key.get(), _hdr->sz_key, avail->stripes,
	    _hash_type, split_key);

	uint8_t pw_digest[_hdr->sz_key];
	pbkdf2(_hash_type,
	    reinterpret_cast<const uint8_t *>(passwd.c_str()),
	    passwd.size(), avail->salt, avail->iterations, pw_digest,
	    sizeof(pw_digest));

	uint8_t pw_crypt[sizeof(split_key)];
	// TODO pw_crypt = encrypt(_hdr->cipher_name, _hdr->cipher_mode,
	//	pw_digest, split_key, sizeof(split_key));

	avail->active = KEY_ENABLED;

	// TODO write_to_disk(avail);
}

void
luks::Luks_header::revoke_slot(uint8_t which)
{
	ensure_mach_key(which, true);
	_hdr->keys[which].active = KEY_DISABLED;
	// see http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html
	// TODO gutmann_erase(key->off_km, hdr->sz_key * key->stripes);
}
