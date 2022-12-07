/* Copyright (c) 2009-2011, Markus Peloquin <markus@cs.wisc.edu>
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

#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <iostream>
#include <sstream>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <openssl/rand.h>

#include "af.hpp"
#include "cipher.hpp"
#include "crypt.hpp"
#include "detect.hpp"
#include "gutmann.hpp"
#include "hash.hpp"
#include "luks.hpp"
#include "pbkdf2.hpp"
#include "os.hpp"
#include "support.hpp"

namespace fluks {
namespace {

const uint16_t	PBKDF2_BENCH_ITER = 10000;

int		read_all(int, void *, size_t);
int		write_all(int, const void *, size_t) noexcept;

int
read_all(int fd, void *buf, size_t count) {
	uint8_t *pos = static_cast<uint8_t *>(buf);
	while (count) {
		ssize_t by = ::read(fd, pos, count);
		if (by < 0)
			return -1;
		if (!by)
			throw Disk_error("premature EOF");
		count -= by;
		pos += by;
	}
	return 0;
}

int
write_all(int fd, const void *buf, size_t count) noexcept {
	const uint8_t *pos = static_cast<const uint8_t *>(buf);
	while (count) {
		ssize_t by = ::write(fd, pos, count);
		if (by < 0)
			return -1;
		count -= by;
		pos += by;
	}
	return 0;
}

} // end anon namespace
}

bool
fluks::check_magic(const struct phdr1 *header) {
	return std::equal(MAGIC, MAGIC + sizeof MAGIC, header->magic);
}

bool
fluks::check_version_1(const struct phdr1 *header) {
	return header->version == 1;
}

fluks::Luks_header::Luks_header(int device, int32_t sz_key,
    const std::string &cipher_spec, const std::string &hash_spec,
    uint32_t mk_iterations, uint32_t stripes) :
	_device(device),
	_hdr(new struct phdr1),
	_master_key(),
	_cipher_spec(),
	_sz_sect(0),
	_hash_type(Hash_traits::type(hash_spec)),
	_proved_passwd(-1),
	_mach_end(true),
	_dirty(true),
	_key_need_erase(NUM_KEYS, false),
	_key_crypt()
{
	_sz_sect = sector_size(device);

	init_cipher_spec(cipher_spec, sz_key);
	_master_key.reset(new uint8_t[_hdr->sz_key]);

	if (_hash_type == hash_type::UNDEFINED)
		throw Bad_spec("unrecognized hash");

	// initialize LUKS header

#ifdef DEBUG
	// for valgrind
	std::fill(_master_key.get(), _master_key.get() + _hdr->sz_key, 0);
#endif
	if (!RAND_bytes(_master_key.get(), _hdr->sz_key))
		throw Ssl_error();

	std::copy(MAGIC, MAGIC + sizeof MAGIC, _hdr->magic);
	_hdr->version = 1;

	// write the canonized hash name into the header
	{
		std::string hash = Hash_traits::traits(_hash_type)->name;
		std::copy(hash.begin(), hash.end(), _hdr->hash_spec);
		_hdr->hash_spec[hash.size()] = '\0';
	}

#ifdef DEBUG
	// for valgrind
	std::fill(_hdr->mk_salt, _hdr->mk_salt + SZ_SALT, 0);
#endif
	if (!RAND_bytes(_hdr->mk_salt, SZ_SALT))
		throw Ssl_error();
	_hdr->mk_iterations = mk_iterations;

	// hash the master key
	pbkdf2(_hash_type, _master_key.get(), _hdr->sz_key,
	    _hdr->mk_salt, SZ_SALT, _hdr->mk_iterations,
	    _hdr->mk_digest, SZ_MK_DIGEST);

	// LUKS defines off_base as
	//	floor(sizeof(phdr1) / sz_sect) + 1,
	// but it is clearly more correct to use
	//	ceil(sizeof(phdr1) / sz_sect).
	// the same goes for km_sectors
	uint32_t off_base = (sizeof(phdr1) + _sz_sect - 1) / _sz_sect;
	uint32_t km_sectors =
	    (stripes * _hdr->sz_key + _sz_sect - 1) / _sz_sect;

	for (uint8_t i = 0; i < NUM_KEYS; i++) {
		_hdr->keys[i].active = KEY_DISABLED;
		_hdr->keys[i].iterations = 0;
		_hdr->keys[i].stripes = stripes;
		_hdr->keys[i].off_km = off_base;

		off_base += km_sectors;
	}

	_hdr->off_payload = off_base;

	// generates a warning with >=gcc-4.6 and <boost-1.49
	boost::uuids::uuid uuid = boost::uuids::random_generator()();
	std::string uuid_str = boost::lexical_cast<std::string>(uuid);
	std::copy(uuid_str.begin(), uuid_str.end(), _hdr->uuid);
}

fluks::Luks_header::Luks_header(int device) :
	_device(device),
	_hdr(new struct phdr1),
	_master_key(),
	_cipher_spec(),
	_sz_sect(0),
	_proved_passwd(-1),
	_mach_end(false),
	_dirty(false),
	_key_need_erase(NUM_KEYS, false),
	_key_crypt()
{
	_sz_sect = sector_size(device);
	if (::lseek(device, 0, SEEK_SET) == static_cast<off_t>(-1))
		throw_errno(errno);
	if (read_all(device, _hdr.get(), sizeof(phdr1)) == -1)
		throw_errno(errno);

	// big-endian -> machine-endian
	set_mach_end(true);

	if (!check_magic(_hdr.get()))
		throw No_header();

	if (!check_version_1(_hdr.get()))
		throw Unsupported_version();

	_hash_type = Hash_traits::type(_hdr->hash_spec);

	if (_hash_type == hash_type::UNDEFINED)
		throw Bad_spec(
		    std::string("undefined hash spec in header: ") +
		    _hdr->hash_spec);

	// recreate the cipher-spec string
	std::string cipher_spec = _hdr->cipher_name;
	if (*_hdr->cipher_mode) {
		cipher_spec += '-';
		cipher_spec += _hdr->cipher_mode;
	}
	init_cipher_spec(cipher_spec, _hdr->sz_key);
}

bool
fluks::Luks_header::read_key(const std::string &passwd, int8_t hint) {
	if (_master_key)
		return false;

	set_mach_end(true);

	std::unique_ptr<uint8_t[]> master_key{new uint8_t[_hdr->sz_key]};
	uint8_t key_digest[SZ_MK_DIGEST];
	uint8_t i;
	uint8_t max;

	if (static_cast<uint16_t>(hint) >= NUM_KEYS) hint = -1;

	if (hint >= 0) {
		i = hint;
		max = hint + 1;
	} else {
		i = 0;
		max = NUM_KEYS;
	}

	// find a slot than can be decrypted with the password, copy the
	// data to _master_key
	for (; i < max; i++) {
		if (_hdr->keys[i].active == KEY_DISABLED) continue;
		decrypt_key(passwd, i, key_digest, master_key.get());

		if (std::equal(key_digest, key_digest + sizeof key_digest,
		    _hdr->mk_digest)) {
			_proved_passwd = i;
			_master_key.reset(new uint8_t[_hdr->sz_key]);
			std::copy(master_key.get(), master_key.get() + _hdr->sz_key,
			    _master_key.get());
			return true;
		}
	}
	return false;
}

void
fluks::Luks_header::add_passwd(
	const std::string &passwd, uint32_t check_time
) {
	struct key	*avail = 0;
	uint8_t		avail_idx = 0;

	if (!_master_key) throw No_private_key();

	set_mach_end(true);

	// find an open slot
	for (uint8_t i = 0; i < NUM_KEYS; i++) {
		if (_hdr->keys[i].active == KEY_DISABLED) {
			avail = _hdr->keys + i;
			avail_idx = i;
			break;
		}
	}
	if (!avail) throw Slots_full();

	size_t sz_split_key = _hdr->sz_key * avail->stripes;
	std::unique_ptr<uint8_t[]> split_key{new uint8_t[sz_split_key]};

#ifdef DEBUG
	// for valgrind
	std::fill(avail->salt, avail->salt + SZ_SALT, 0);
#endif
	if (!RAND_bytes(avail->salt, SZ_SALT))
		throw Ssl_error();
	af_split(_master_key.get(), _hdr->sz_key, avail->stripes,
	    _hash_type, split_key.get());

	std::unique_ptr<uint8_t[]> pw_digest{new uint8_t[_hdr->sz_key]};

	// benchmark the PBKDF2 function
	auto timer_start = std::chrono::high_resolution_clock::now();
	pbkdf2(_hash_type,
	    reinterpret_cast<const uint8_t *>(passwd.c_str()), passwd.size(),
	    avail->salt, SZ_SALT, PBKDF2_BENCH_ITER,
	    pw_digest.get(), _hdr->sz_key);
	auto timer_end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<uint64_t, std::nano> elapsed =
	    timer_end - timer_start;

	// This would only overload uint64_t at ~512.4 hours.
	avail->iterations = static_cast<uint32_t>(
	    static_cast<uint64_t>(PBKDF2_BENCH_ITER) * check_time * 1000 /
	    elapsed.count());

	// compute digest for realsies
	pbkdf2(_hash_type,
	    reinterpret_cast<const uint8_t *>(passwd.c_str()), passwd.size(),
	    avail->salt, SZ_SALT, avail->iterations,
	    pw_digest.get(), _hdr->sz_key);

	// encrypt the master key with pw_digest
	std::shared_ptr<Crypter> crypter = Crypter::create(pw_digest.get(),
	    _hdr->sz_key, *_cipher_spec);
	_key_crypt[avail_idx].reset(new uint8_t[sz_split_key]);
	crypter->encrypt(avail->off_km, _sz_sect,
	    split_key.get(), sz_split_key, _key_crypt[avail_idx].get());

	// verify that decryption works just as well
	std::unique_ptr<uint8_t[]> crypt_check{new uint8_t[sz_split_key]};
	crypter->decrypt(avail->off_km, _sz_sect,
	    _key_crypt[avail_idx].get(), sz_split_key, crypt_check.get());

	Assert(std::equal(crypt_check.get(), crypt_check.get() + sz_split_key,
	    split_key.get()), "ciphertext couldn't be decrypted");

	avail->active = KEY_ENABLED;
	_dirty = true;
}

bool
fluks::Luks_header::check_supported(std::ostream *out, uint16_t max_version) {
	uint16_t	vers;
	bool		good = true;

	vers = Cipher_traits::traits(_cipher_spec->type_cipher())->
	    luks_version;
	if (!vers || (max_version && vers > max_version)) {
		if (!out) return false;
		good = false;
		*out << "WARNING: using cipher not in LUKS spec.\n";
	}
	vers = block_mode_info::version(_cipher_spec->type_block_mode());
	if (!vers || (max_version && vers > max_version)) {
		if (!out) return false;
		good = false;
		*out << "WARNING: using block mode not in LUKS spec.\n";
	}
	vers = iv_mode_info::version(_cipher_spec->type_iv_mode());
	if (!vers || (max_version && vers > max_version)) {
		if (!out) return false;
		good = false;
		*out << "WARNING: using IV mode not in LUKS spec.\n";
	}
	vers = Hash_traits::traits(_cipher_spec->type_iv_hash())->
	    luks_version;
	if (!vers || (max_version && vers > max_version)) {
		if (!out) return false;
		good = false;
		*out << "WARNING: using IV hash not in LUKS spec.\n";
	}
	vers = Hash_traits::traits(_hash_type)->luks_version;
	if (!vers || (max_version && vers > max_version)) {
		if (!out) return false;
		good = false;
		*out << "WARNING: using hash not in LUKS spec.\n";
	}
	if (!good)
		*out << "WARNING: these specs will not work with other LUKS "
		    "implementations.\n";

	return good;
}

std::string
fluks::Luks_header::info() const {
	const_cast<Luks_header *>(this)->set_mach_end(true);
	std::ostringstream out;

	out <<   "version                             " << _hdr->version
	    << "\ncipher                              " << _hdr->cipher_name
	    << "\ncipher mode                         " << _hdr->cipher_mode
	    << "\nhash spec                           " << _hdr->hash_spec
	    << "\npayload start sector                " << _hdr->off_payload
	    << "\nmaster key size                     " << _hdr->sz_key
	    << "\nmaster key iterations               " << _hdr->mk_iterations
	    << "\nuuid                                " << _hdr->uuid;
	for (uint16_t i = 0; i < NUM_KEYS; i++) {
		out << "\nkey " << i << " state                         "
		    << (_hdr->keys[i].active == KEY_ENABLED ?
		    "ENABLED" : "DISABLED")
		    << "\nkey " << i << " iterations                    "
		    << _hdr->keys[i].iterations
		    << "\nkey " << i << " key material sector offset    "
		    << _hdr->keys[i].off_km
		    << "\nkey " << i << " stripes                       "
		    << _hdr->keys[i].stripes;
	}
	return out.str();
}

void
fluks::Luks_header::revoke_slot(uint8_t which) {
	if (!_master_key)
		throw Safety("will not allow a revokation while the "
		    "master key is unknown");
	if (which == _proved_passwd)
		throw Safety("only the passwords not used to decrypt the "
		    "master key are allowed to be revoked");

	set_mach_end(true);

	_hdr->keys[which].active = KEY_DISABLED;
	_dirty = true;
	_key_need_erase[which] = true;
}

void
fluks::Luks_header::wipe() {
	if (!_master_key)
		throw Safety("will not allow the header to be wiped while "
		    "the master key is unknown");

	gutmann_erase(_device, 0, _hdr->off_payload);
}

void
fluks::Luks_header::save() {
	if (!_dirty) return;

	set_mach_end(true);

	// first erase old keys and then commit new keys
	for (uint8_t i = 0; i < NUM_KEYS; i++) {
		if (_key_need_erase[i]) {
			gutmann_erase(_device,
			    _hdr->keys[i].off_km * _sz_sect,
			    _hdr->sz_key * _hdr->keys[i].stripes);
			_key_need_erase[i] = false;
		}

		if (_key_crypt[i]) {
			if (::lseek(_device, _hdr->keys[i].off_km * _sz_sect,
			    SEEK_SET) == -1) {
				// "writing key material: seek error"
				throw_errno(errno);
			}

			if (write_all(_device, _key_crypt[i].get(),
			    _hdr->sz_key * _hdr->keys[i].stripes) == -1) {
				// "writing key material: write error"
				throw_errno(errno);
			}
			_key_crypt[i].reset();
		}
	}

	if (_dirty) {
		// ensure big-endian
		set_mach_end(false);

		if (::lseek(_device, 0, SEEK_SET) == -1) {
			// "writing header: seek error"
			throw_errno(errno);
		}

		if (write_all(_device, _hdr.get(), sizeof(phdr1)) ==
		    -1) {
			// "writing header: write error"
			throw_errno(errno);
		}

		_dirty = false;
	}

	// run dmsetup
	// NAME = device-mapper name
	// LOGICAL_START_SECTOR
	// dmsetup create NAME --table "LOGICAL_START_SECTOR NUM_SECTORS crypt CIPHER KEY IV_OFFSET DEVICE_PATH OFFSET"
}

// initializes the values of the cipher-spec enums, the cipher-spec
// strings in the LUKS header, and the sz_key value in the LUKS header,
// throwing Bad_spec as necessary
void
fluks::Luks_header::init_cipher_spec(const std::string &cipher_spec,
    int32_t sz_key) {
	set_mach_end(true);

	// parse and check
	_cipher_spec.reset(new Cipher_spec(sz_key, cipher_spec));

	if (sz_key == -1) {
		// use the largest possible size
		const Cipher_traits *traits =
		    Cipher_traits::traits(_cipher_spec->type_cipher());
		const std::vector<uint16_t> &sizes = traits->key_sizes;
		sz_key = sizes.back();
	}
	_hdr->sz_key = sz_key;

	// recreate a canonical cipher spec
	std::string cipher = _cipher_spec->canon_cipher();
	std::string mode = _cipher_spec->canon_mode();

	// copy specs (back) into header
	std::copy(cipher.begin(), cipher.end(), _hdr->cipher_name);
	_hdr->cipher_name[cipher.size()] = '\0';
	std::copy(mode.begin(), mode.end(), _hdr->cipher_mode);
	_hdr->cipher_mode[mode.size()] = '\0';
}

int8_t
fluks::Luks_header::locate_passwd(const std::string &passwd) {
	set_mach_end(true);

	uint8_t key_digest[SZ_MK_DIGEST];
	std::unique_ptr<uint8_t[]> master_key{new uint8_t[_hdr->sz_key]};

	// find the first slot that can be decrypted with the password
	for (uint8_t i = 0; i < NUM_KEYS; i++) {
		if (_hdr->keys[i].active == KEY_DISABLED) continue;
		decrypt_key(passwd, i, key_digest, master_key.get());

		if (std::equal(key_digest, key_digest + sizeof key_digest,
		    _hdr->mk_digest))
			return i;
	}
	return -1;
}

// key_digest should be as large as the digest size of the hash
// master_key should be as large as _hdr->sz_key
void
fluks::Luks_header::decrypt_key(const std::string &passwd, uint8_t slot,
    uint8_t key_digest[SZ_MK_DIGEST], uint8_t *master_key) {
	set_mach_end(true);

	std::unique_ptr<uint8_t[]> pw_digest{new uint8_t[_hdr->sz_key]};
	struct key *key = _hdr->keys + slot;
	size_t sz_split_key = _hdr->sz_key * key->stripes;
	std::unique_ptr<uint8_t[]> key_crypt{new uint8_t[sz_split_key]};
	std::unique_ptr<uint8_t[]> split_key{new uint8_t[sz_split_key]};

	// password => pw_digest
	pbkdf2(_hash_type,
	    reinterpret_cast<const uint8_t *>(passwd.c_str()), passwd.size(),
	    key->salt, SZ_SALT, key->iterations,
	    pw_digest.get(), _hdr->sz_key);

	// disk => key_crypt
	if (::lseek(_device, key->off_km * _sz_sect, SEEK_SET) ==
	    static_cast<off_t>(-1)) {
		// "failed to seek to key material"
		throw_errno(errno);
	}

	if (read_all(_device, key_crypt.get(), sz_split_key) == -1) {
		// "failed to read key material"
		throw_errno(errno);
	}

	// (pw_digest, key_crypt) => split_key
	{
		std::shared_ptr<Crypter> crypter = Crypter::create(
		    pw_digest.get(), _hdr->sz_key, *_cipher_spec);
		crypter->decrypt(key->off_km, _sz_sect,
		    key_crypt.get(), sz_split_key, split_key.get());
	}

	// split_key => master_key
	af_merge(split_key.get(), _hdr->sz_key, key->stripes,
	    _hash_type, master_key);

	// master_key => key_digest
	pbkdf2(_hash_type,
	    master_key, _hdr->sz_key,
	    _hdr->mk_salt, SZ_SALT, _hdr->mk_iterations,
	    key_digest, SZ_MK_DIGEST);
}
