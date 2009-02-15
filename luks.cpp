#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <string>

#include <openssl/rand.h>

#include "af.hpp"
#include "hash.hpp"
#include "luks.hpp"
#include "pbkdf2.hpp"

void
luks::add_password(struct header *luks, const std::string &password)
{
	struct phdr1 *hdr = luks->hdr.get();
	struct key *avail = 0;

	assert(luks->master_key);

	// find an open slot
	for (size_t i = 0; i < NUM_KEYS; i++)
		if (hdr->keys[i].active == KEY_DISABLED) {
			avail = hdr->keys + i;
			break;
		}
	if (!avail) {
		// oh shit (TODO)
		exit(666);
	}

	uint8_t split_key[hdr->sz_key * avail->stripes];

	// TODO PBKDF2_iterations_per_second = benchmark system
	// avail.iterations = PBKDF2_iterations_per_second *
	//	intented_password_checking_time

	RAND_bytes(avail->salt, SZ_SALT);
	af_split(luks->master_key.get(), hdr->sz_key, avail->stripes,
	    luks->hash_type, split_key);

	uint8_t pw_digest[hdr->sz_key];
	pbkdf2(luks->hash_type,
	    reinterpret_cast<const uint8_t *>(password.c_str()),
	    password.size(), avail->salt, avail->iterations, pw_digest,
	    sizeof(pw_digest));

	uint8_t pw_crypt[sizeof(split_key)];
	// TODO pw_crypt = encrypt(hdr->cipher_name, hdr->cipher_mode,
	//	pw_digest, split_key, sizeof(split_key));

	// TODO write_to_disk(pw_crypt, avail->off_km, sizeof(pw_crypt));
	avail->active = KEY_ENABLED;

	// TODO write_to_disk(avail);
}

void
luks::initialize(struct header *luks, size_t sz_key,
    const std::string &cipher_name, const std::string &cipher_mode,
    const std::string &hash_spec, uint32_t mk_iter, size_t stripes)
{
	struct phdr1 *hdr = luks->hdr.get();

	assert(cipher_name.size() + 1 < SZ_CIPHER_NAME);
	assert(cipher_mode.size() + 1 < SZ_CIPHER_MODE);
	assert(hash_spec.size() + 1 < SZ_HASH_SPEC);
	// TODO validate specs?

	luks->master_key.reset(new uint8_t[sz_key]);
	RAND_bytes(luks->master_key.get(), hdr->sz_key);

	memcpy(hdr->magic, MAGIC, sizeof(MAGIC));
	hdr->version = 1;
	memcpy(hdr->cipher_name, cipher_name.c_str(), cipher_name.size() + 1);
	memcpy(hdr->cipher_mode, cipher_mode.c_str(), cipher_mode.size() + 1);
	memcpy(hdr->hash_spec, hash_spec.c_str(), cipher_mode.size() + 1);
	hdr->sz_key = sz_key;
	RAND_bytes(hdr->mk_salt, SZ_SALT);
	hdr->mk_iterations = mk_iter;

	pbkdf2(luks->hash_type, luks->master_key.get(), sz_key, hdr->mk_salt,
	    hdr->mk_iterations, hdr->mk_digest, SZ_MK_DIGEST);

	/*TODO (totally fake) */ const uint32_t SECTOR_SIZE = 2048;
	uint32_t off_base = sizeof(phdr1) / SECTOR_SIZE + 1;
	uint32_t km_sectors = (stripes * hdr->sz_key) / SECTOR_SIZE + 1;

	for (size_t i = 0; i < NUM_KEYS; i++) {
		hdr->keys[i].active = KEY_DISABLED;
		hdr->keys[i].stripes = stripes;
		hdr->keys[i].off_km = off_base;

		off_base += km_sectors;
	}

	hdr->off_payload = off_base;
	//TODO hdr->uuid = generate_uuid()

	//TODO write_to_disk(hdr)
}

void
luks::read_key(struct header *luks, const std::string &password)
{
	struct phdr1 *hdr = luks->hdr.get();

	uint8_t pw_digest[hdr->sz_key];
	uint8_t key_merged[hdr->sz_key];
	uint8_t key_digest[hash_size(luks->hash_type)];
	struct key *key;

	for (size_t i = 0; i < NUM_KEYS; i++) {
		key = hdr->keys + i;

		uint8_t key_crypt[hdr->sz_key * key->stripes];
		uint8_t key_splitted[sizeof(key_crypt)];

		// password => pw_digest
		pbkdf2(luks->hash_type,
		    reinterpret_cast<const uint8_t *>(password.c_str()),
		    password.size(), key->salt, key->iterations, pw_digest,
		    sizeof(pw_digest));

		// disk => key_crypt
		// TODO key_crypt = read(key->off_km, sizeof(pw_disk_crypt));

		// (pw_digest, key_crypt) => key_splitted
		// TODO key_splitted = decrypt(hdr->cipher_name,
		//	hdr->cipher_mode, pw_digest, key_crypt,
		//	sizeof(key_crypt));

		// key_splitted => key_merged
		af_merge(key_splitted, sizeof(key_splitted), key->stripes,
		    luks->hash_type, key_merged);

		// key_merged => key_digest
		pbkdf2(luks->hash_type, key_merged, sizeof(key_merged),
		    hdr->mk_salt, hdr->mk_iterations, key_digest,
		    SZ_MK_DIGEST);

		if (std::equal(pw_digest, key_digest + sizeof(key_digest),
		    hdr->mk_digest)) {
			if (!luks->master_key) {
				luks->master_key.reset(
				    new uint8_t[hdr->sz_key]);
				memcpy(luks->master_key.get(), key_merged,
				    sizeof(key_merged));
			}
		}
	}
}

void
luks::revoke_password(struct header *luks, size_t which)
{
	phdr1 *hdr = luks->hdr.get();
	key *key = hdr->keys + which;
	key->active = KEY_DISABLED;
	// see http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html
	// TODO gutmann_erase(key->off_km, hdr->sz_key * key->stripes);
}
