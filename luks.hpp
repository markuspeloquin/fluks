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

#ifndef FLUKS_LUKS_HPP
#define FLUKS_LUKS_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <vector>
#include <boost/system/system_error.hpp>

#include "cipher_spec.hpp"
#include "errors.hpp"
#include "os.hpp"
#include "sys_fstream.hpp"

namespace fluks {

// header/key buffer sizes
const size_t	NUM_KEYS = 8;
const size_t	SZ_CIPHER_MODE = 0x20;
const size_t	SZ_CIPHER_NAME = 0x20;
const size_t	SZ_HASH_SPEC = 0x20;
const size_t	SZ_MK_DIGEST = 0x14;
const size_t	SZ_SALT = 0x20;
const size_t	SZ_UUID = 0x28;

// header/key values
const uint8_t	MAGIC[] = { 'L', 'U', 'K', 'S', 0xba, 0xbe };
const uint32_t	KEY_DISABLED = 0x0000dead;	// note: nice
const uint32_t	KEY_ENABLED = 0x00ac71f3;

// default value for phdr::mk_iterations
const uint32_t	NUM_MK_ITER = 10;

// default number of stripes for af_split() and af_merge()
const size_t	NUM_STRIPES = 4000;


/** LUKS version 1 key data header
 *
 * On the disk, all multibyte values are stored in big-endian.
 */
struct key {
// annotated with hex offsets
	/** One of { <code>KEY_ENABLED</code>, <code>KEY_DISABLED</code> } */
/*00*/	uint32_t	active;
/*04*/	uint32_t	iterations;	/**< PBKDF2 iterations */
/*08*/	uint8_t		salt[SZ_SALT];	/**< PBKDF2 salt */
/*28*/	uint32_t	off_km;		/**< Sector of %key material */
/*2c*/	uint32_t	stripes;	/**< Anti-forensic stripe count */
// 30 (48 bytes)
};

/** LUKS version 1 header
 *
 * On the disk, all multibyte values are stored in big-endian.
 */
struct phdr1 {
// annotated with hex offsets
/*00*/	uint8_t		magic[sizeof(MAGIC)];
/*06*/	uint16_t	version;
/*08*/	char		cipher_name[SZ_CIPHER_NAME];
/*28*/	char		cipher_mode[SZ_CIPHER_MODE];
/*48*/	char		hash_spec[SZ_HASH_SPEC];
/*68*/	uint32_t	off_payload;	/**< Start sector of bulk data */
/*6c*/	uint32_t	sz_key;		/**< Count of private key bytes */
/*70*/	uint8_t		mk_digest[SZ_MK_DIGEST];
/*84*/	uint8_t		mk_salt[SZ_SALT];
/*a4*/	uint32_t	mk_iterations;
/*a8*/	char		uuid[SZ_UUID];
/*d0*/	struct key	keys[NUM_KEYS];
// 250 (592 bytes)
};


/** Check if LUKS magic is present (to indicate that it's a LUKS header or
 * not)
 *
 * \param header	The possible header
 * \retval true		Magic is present
 * \retval false	Magic is not present
 */
bool	check_magic(const struct phdr1 *header);


/** Check if a header is version LUKS v1
 *
 * \param header	The header in machine-endian
 * \retval true		The header is LUKS v1
 * \retval false	The header is not LUKS v1
 * \see endian_switch()
 */
bool	check_version_1(const struct phdr1 *header);


// switch to/from BE
inline void	endian_switch(struct phdr1 *, bool process_keys);
inline void	endian_switch(struct key *);


/** A LUKS header. */
class Luks_header {
public:
	/** Create a new header
	 *
	 * \param device	The device to read/write
	 * \param sz_key	The byte length of the master key, or -1 for
	 *	the largest possible for the cipher.
	 * \param cipher_spec	Cipher to encrypt with. Format is
	 *	CIPHER [ - CHAINMODE [ - IV_OPTS [ : IV_MODE ]]], where
	 *	brackets indicate optional parts and without spaces.
	 * \param hash_spec	Hash to use for the master key hash and the
	 *	password (the hash is the key for the master key).
	 * \param mk_iterations	The iterations to use in the PBKDF2 algorithm,
	 *	increasing the parity of its hashes.
	 * \param stripes	Dramatically increases the length and entropy
	 *	of the master key before the digest is computed.
	 * \throw Bad_spec	One of the cipher/hash specs is invalid.
	 * \throw boost::system::system_error	Error encountered determining
	 *	the sector size.
	 */
	Luks_header(int device, int32_t sz_key,
	    const std::string &cipher_spec, const std::string &hash_spec,
	    uint32_t mk_iterations=NUM_MK_ITER, uint32_t stripes=NUM_STRIPES)
	    noexcept(false);

	/** Read a header from the disk
	 *
	 * \param device	The device to read/write
	 * \throw Bad_spec
	 * \throw Disk_error
	 * \throw No_header
	 * \throw Unsupported_version
	 * \throw boost::system::system_error
	 */
	Luks_header(int device) noexcept(false);

	~Luks_header() {}

	/** Get the full, canonized cipher spec
	 *
	 * \return  The cipher spec, for use by dm-crypt.
	 */
	const std::string cipher_spec() const
	{
		std::string res = _hdr->cipher_name;
		if (*_hdr->cipher_mode) {
			res += '-';
			res += _hdr->cipher_mode;
		}
		return res;
	}

	/** Get the master key
	 *
	 * \return	A pair containing the master key and its size. If the
	 *	master key hasn't been decrypted yet, the key will be nullptr.
	 */
	std::pair<const uint8_t *, size_t> master_key() const
	{
		const_cast<Luks_header *>(this)->set_mach_end(true);
		return std::make_pair(_master_key.get(), _hdr->sz_key);
	}

	/** The size of the header and key material in sectors
	 *
	 * This is the same as the start sector of the partition's data.
	 *
	 * \return The size in sectors
	 */
	uint32_t sectors() const
	{
		const_cast<Luks_header *>(this)->set_mach_end(true);
		return _hdr->off_payload;
	}

	/** The UUID of the partition.
	 *
	 * \return  The UUID.
	 */
	std::string uuid() const
	{	return std::string(_hdr->uuid); }

	/** Decrypt the private key
	 *
	 * \param passwd	The password to encrypt the master key with.
	 * \param hint	If non-negative, only this index will be tested.
	 * \retval true	The key was decrypted.
	 * \retval false	The key was already decrypted, or it failed
	 *			to decrypt.
	 * \throw Disk_error	A device open/seek/read error occurred.
	 */
	bool read_key(const std::string &passwd, int8_t hint=-1)
	    noexcept(false);

	/** Add a password for the private key
	 *
	 * \param passwd	The password to encrypt the key with.
	 * \param check_time	The time (in microseconds) to spend on the
	 *	PBKDF2 (password-based key derivation function). It will of
	 *	course depend on CPU load and throttling.
	 * \throw No_private_key	The private key hasn't been decrypted
	 *	yet.
	 * \throw Slots_full	All slots are enabled already.
	 */
	void add_passwd(const std::string &passwd, uint32_t check_time=500000)
	    throw (No_private_key, Slots_full);

	/** Check whether the cipher and hash specs are supported in LUKS.
	 *
	 * \param out	A pointer to a stream to print warnings to, or else
	 *	NULL to print nothing.
	 * \param max_version	(optional) If non-zero, any parameters beyond
	 *	this value will see a warning. In any case, parameters not in
	 *	any LUKS spec will see a warning.
	 * \return	<code>true</code> iff the cipher and hash specs are
	 *	supported.
	 */
	bool check_supported(std::ostream *out=0, uint16_t max_version=0);

	/** Format the values in the header, except for the salts and digest.
	 *
	 * \return	A string representation of the header. */
	std::string info() const;

	/** Disable a password slot
	 *
	 * \param which		The index of the key slot to revoke.
	 * \throw Safety	Either the private key hasn't been decrypted
	 *	yet or it was decrypted with the same password being deleted.
	 */
	void revoke_slot(uint8_t which) noexcept(false);

	/** Disable a password
	 *
	 * \param passwd	The password to revoke.
	 * \retval false	The password slot wasn't found.
	 * \throw Disk_error	Failed to read key material.
	 * \throw Safety	Either the private key hasn't been decrypted
	 *	yet or it was decrypted with the same password being deleted.
	 */
	bool revoke_passwd(const std::string &passwd)
	    throw (Disk_error, Safety)
	{
		int8_t which = locate_passwd(passwd);
		if (which == -1) return false;
		revoke_slot(which);
		return true;
	}

	/** Securely erase the LUKS header using the Gutmann algorithm.
	 *
	 * \throw Disk_error	Some write/seek failure.
	 * \throw Safety	The private key hasn't been decrypted yet.
	 */
	void wipe() throw (Disk_error, Safety);

	/** Commit the header and/or new key material to the disk.
	 *
	 * \throw Disk_error	Some write/seek failure.
	 */
	void save() noexcept(false);

private:
	void set_mach_end(bool which)
	{
		if (_mach_end != which) {
			endian_switch(_hdr.get(), true);
			_mach_end = which;
		}
	}
	void init_cipher_spec(const std::string &cipher_spec, int32_t sz_key)
	    noexcept(false);

	int8_t locate_passwd(const std::string &passwd) noexcept(false);

	void decrypt_key(const std::string &passwd, uint8_t slot,
	    uint8_t key_digest[SZ_MK_DIGEST], uint8_t *master_key);

	Luks_header(const Luks_header &l) {}
	void operator=(const Luks_header &l) {}

	int				_device;
	std::unique_ptr<struct phdr1>	_hdr;
	std::unique_ptr<uint8_t>	_master_key;
	std::unique_ptr<Cipher_spec>	_cipher_spec;
	uint16_t			_sz_sect;
	hash_type			_hash_type;

	// the index of the entered password (-1=invalid)
	int8_t				_proved_passwd;
	// the current endian the header (machine or big)
	bool				_mach_end;
	// has the header been changed
	bool				_dirty;
	// which keys need to be erased
	std::vector<uint8_t>		_key_need_erase;
	// encrypted keys that need to be written to disk
	std::unique_ptr<uint8_t>	_key_crypt[NUM_KEYS];
};


}

#include "luks_private.hpp"

#endif
