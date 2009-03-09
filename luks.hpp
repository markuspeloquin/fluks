#ifndef LUKS_HPP
#define LUKS_HPP

#include <stdint.h> // no cstdint yet

#include <cstddef>
#include <string>
#include <vector>
#include <boost/scoped_array.hpp>
#include <boost/scoped_ptr.hpp>

#include "errors.hpp"
#include "os.hpp"

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
	/** One of { \link KEY_ENABLED\endlink, \link KEY_DISABLED\endlink } */
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
/*28*/	char		block_mode[SZ_CIPHER_MODE];
/*48*/	char		hash_spec[SZ_HASH_SPEC];
/*68*/	uint32_t	off_payload;	/**< Start sector of bulk data */
/*6c*/	uint32_t	sz_key;		/**< Count of private key bytes */
/*70*/	uint8_t		mk_digest[SZ_MK_DIGEST];
/*84*/	uint8_t		mk_salt[SZ_SALT];
/*a4*/	uint32_t	mk_iterations;
/*a8*/	char		uuid_part[SZ_UUID];
/*d0*/	struct key	keys[NUM_KEYS];
// 250 (592 bytes)
};


/** Ciphers supported by <em>fluks</em> */
enum cipher_type {
	CT_UNDEFINED = 0,
	CT_AES,
	CT_BLOWFISH,
	CT_CAST5,
	CT_CAST6,
	CT_DES3,
	CT_TWOFISH,
	CT_SERPENT
};


/** Cipher block modes supported by <em>fluks</em> */
enum block_mode {
	BM_UNDEFINED = 0,
	BM_CBC, /**< Cipher Block Chaining */
	BM_CTR, /**< Counter */
	/** Cipher Text Stealing
	 *
	 * Described in RFC 2040, Section 8 */
	BM_ECB,
	BM_PCBC /**< Propogating Cipher Block Chaining */
};


enum iv_mode {
	IM_UNDEFINED = 0,
	IM_PLAIN,
	IM_ESSIV
};


/** Hash types supported by <em>fluks</em>
 *
 * Tiger is optimized for 64-bit architectures, designed by the same folks
 * who brought you the Serpent cipher.  Tiger/{128,160} are just truncated
 * versions of Tiger/192.
 *
 * Along with SHA-{1,256,384,512} and RMD-{128,160}, WHIRLPOOL is included
 * in ISO/IEC's list of recommended hash functions (10118-3), and is
 * also recommended by NESSIE.  WHIRLPOOL-{256,384} are just
 * truncated versions.
 */
enum hash_type {
	HT_UNDEFINED = 0,
	HT_MD5,	/**< (you probably should not use this) */
	HT_RMD160,	/**< Possibly better knows as RIPEMD-160 */
	HT_SHA1,
	HT_SHA224,
	HT_SHA256,
	HT_SHA384,
	HT_SHA512,
	HT_TIGER128,
	HT_TIGER160,
	HT_TIGER192,
	HT_WHIRLPOOL256,
	HT_WHIRLPOOL384,
	HT_WHIRLPOOL512
};


// switch to/from LE
inline uint16_t host_little(uint16_t);
inline uint32_t	host_little(uint32_t);

// switch to/from BE
inline void	endian_switch(struct phdr1 *, bool process_keys);
inline void	endian_switch(struct key *);


/** A LUKS header. */
class Luks_header {
public:
	/** Create a new header
	 *
	 * \param device	The pathname of the device.
	 * \param sz_key	The byte length of the master key.
	 * \param cipher_spec	Cipher to encrypt with.  Format is
	 *	CIPHER [ - CHAINMODE [ - IV_OPTS [ : IV_MODE ]]], where
	 *	brackets indicate optional parts and without spaces.
	 * \param hash_spec	Hash to use for the master key hash and the
	 *	password (the hash is the key for the master key).
	 * \param mk_iterations	The iterations to use in the PBKDF2 algorithm,
	 *	increasing the parity of its hashes.
	 * \param stripes	Dramatically increases the length and entropy
	 *	of the master key before the digest is computed.
	 * \throw Bad_spec	One of the cipher/hash specs is invalid.
	 */
	Luks_header(const std::string &device, uint32_t sz_key,
	    const std::string &cipher_spec, const std::string &hash_spec,
	    uint32_t mk_iterations=NUM_MK_ITER, uint32_t stripes=NUM_STRIPES)
		throw (Bad_spec, Unix_error);

	/** Read a header from the disk
	 *
	 * \param device	I don't know what to do with this yet.
	 */
	Luks_header(const std::string &device);

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
	 * \param check_time	The time (in microseconds) to check the key
	 *	for.
	 * \throw No_private_key	The private key hasn't been
	 *	decrypted yet.
	 * \throw Slots_full	All slots are enabled already.
	 */
	void add_passwd(const std::string &passwd, uint32_t check_time=500000)
	    throw (No_private_key, Slots_full);

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

	void save() throw (Unix_error);

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
	uint16_t			_sz_sect;
	enum hash_type			_hash_type;
	enum cipher_type		_cipher_type;
	enum block_mode			_block_mode;
	enum iv_mode			_iv_mode;
	enum hash_type			_iv_hash;

	std::vector<bool>		_key_mach_end;
	bool				_hdr_mach_end;
};


enum block_mode get_block_mode(const std::string &mode);
enum iv_mode	get_iv_mode(const std::string &name);


}

#include "luks_private.hpp"

#endif
