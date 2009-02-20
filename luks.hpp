#ifndef LUKS_HPP
#define LUKS_HPP

#include <stdint.h> // no cstdint yet

#include <cstddef>
#include <exception>
#include <string>
#include <vector>
#include <boost/scoped_array.hpp>
#include <boost/scoped_ptr.hpp>

namespace luks {

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
	/**
	 * One of {\link KEY_ENABLED\endlink, \link KEY_DISABLED\endlink} */
/*00*/	uint32_t	active;
	/** PBKDF2 iterations */
/*04*/	uint32_t	iterations;
	/** PBKDF2 salt */
/*08*/	uint8_t		salt[SZ_SALT];
	/** Sector of %key material */
/*28*/	uint32_t	off_km;
	/** Anti-forensic stripe count */
/*2c*/	uint32_t	stripes;
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
	/** Start sector of bulk data */
/*68*/	uint32_t	off_payload;
	/** Count of private key bytes */
/*6c*/	uint32_t	sz_key;
/*70*/	uint8_t		mk_digest[SZ_MK_DIGEST];
/*84*/	uint8_t		mk_salt[SZ_SALT];
/*a4*/	uint32_t	mk_iterations;
/*a8*/	char		uuid_part[SZ_UUID];
/*d0*/	struct key	keys[NUM_KEYS];
// 250 (592 bytes)
};


/** Hash types supported by <em>fluks</em> */
enum hash_type {
	HT_MD5,
	/**
	 * Also known as RIPEMD-160, the RACE Integrity Primitives
	 * Evaluation Message Digest.
	 */
	HT_RMD160,
	HT_SHA1,
	HT_SHA224,
	HT_SHA256,
	HT_SHA384,
	HT_SHA512,
	HT_UNDEFINED
};


// switch to/from BE
inline void	endian_switch(struct phdr1 *, bool process_keys);
inline void	endian_switch(struct key *);


struct Slots_full : std::exception {
	~Slots_full() throw() {}

	const char *what() const throw ()
	{	return "All key slots are used."; }
};


struct Bad_spec : std::exception {
	Bad_spec(const std::string &msg) : _msg("Bad crypto spec: ")
	{
		_msg += msg;
		_msg += '.';
	}
	~Bad_spec() throw () {}

	const char *what() const throw ()
	{	return _msg.c_str(); }

	std::string _msg;
};

/** A LUKS header. */
class Luks_header {
public:
	/** Create a new header
	 *
	 * \param sz_key	The byte length of the master key.
	 * \param cipher_name	Cipher to encrypt with (e.g. twofish, aes).
	 * \param cipher_mode	Cipher mode (e.g. cbc-plain, cbc-essiv:sha384).
	 * \param hash_spec	Hash to use for the master key hash and the
	 *	password (the hash is the key for the master key).
	 * \param mk_iterations	The iterations to use in the PBKDF2 algorithm,
	 *	increasing the parity of its hashes.
	 * \param stripes	Dramatically increases the length and entropy
	 *	of the master key before the digest is computed.
	 * \throw Bad_spec	One of the cipher/hash specs is invalid.
	 */
	Luks_header(uint32_t sz_key, const std::string &cipher_name,
	    const std::string &cipher_mode, const std::string &hash_spec,
	    uint32_t mk_iterations=NUM_MK_ITER, uint32_t stripes=NUM_STRIPES)
		throw (Bad_spec);

	/** Read a header from the disk
	 *
	 * \param off		I don't know what to do with this yet.
	 */
	Luks_header(off_t off);

	~Luks_header() {}

	/** Decrypt the private key
	 *
	 * \param passwd	The password to encrypt the master key with.
	 * \param hint	If non-negative, only this index will be tested.
	 * \retval true	The key was decrypted.
	 * \retval false	The key was already decrypted, or it failed
	 *			to decrypt.
	 */
	bool read_key(const std::string &passwd, int8_t hint=-1);

	/** Add a password for the private key
	 *
	 * \param passwd	The password to encrypt the key with.
	 * \throw Slots_full	All slots are enabled already.
	 */
	void add_passwd(const std::string &passwd)
		throw (Slots_full);

	/** Disable a password slot
	 *
	 * \param which	The index of the key slot to revoke.
	 */
	void revoke_slot(uint8_t which);

	/** Get the master key
	 *
	 * \retval nullptr	The key hasn't been decrypted yet.
	 */
	uint8_t *master_key() const
	{	return _master_key.get(); }

private:
	void ensure_mach_hdr(bool which)
	{
		if (_hdr_mach_end != which) {
			endian_switch(_hdr.get(), false);
			_hdr_mach_end = true;
		}
	}
	void ensure_mach_key(uint8_t i, bool which)
	{
		if (_key_mach_end[i] != which) {
			endian_switch(_hdr->keys + i);
			_key_mach_end[i] = true;
		}
	}

	Luks_header(const Luks_header &l) {}
	void operator=(const Luks_header &l) {}

	boost::scoped_ptr<struct phdr1>	_hdr;
	boost::scoped_array<uint8_t>	_master_key;
	enum hash_type			_hash_type;

	std::vector<bool>		_key_mach_end;
	bool				_hdr_mach_end;
};

}

#include "luks_private.hpp"

#endif
