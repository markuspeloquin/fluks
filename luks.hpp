#ifndef LUKS_HPP
#define LUKS_HPP

#include <stdint.h> // no cstdint yet

#include <cstddef>
#include <string>
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
const uint32_t	KEY_DISABLED = 0x0000dead;		// note: nice
const uint32_t	KEY_ENABLED = 0x00ac71f3;

// default value for phdr::mk_iterations
const uint32_t	NUM_MK_ITER = 10;

// default argument for the luks::af_[...] functions
const size_t	NUM_STRIPES = 4000;


// all multi-byte integers are BE; use luks_endian_[...] if necessary; each
// field annotated with the hex offset
struct key {
/*00*/	uint32_t	active;		// one of KEY_[...]
/*04*/	uint32_t	iterations;	// PBKDF2 iterations
/*08*/	uint8_t		salt[SZ_SALT];	// PBKDF2 salt
/*28*/	uint32_t	off_km;		// sector of key material
/*2c*/	uint32_t	stripes;	// anti-forensic stripe count
// 30 (48 bytes)
};

// all multi-byte integers are BE; use luks_endian_[...] if necessary; each
// field annotated with the hex offset
struct phdr1 {
/*00*/	uint8_t		magic[sizeof(MAGIC)];
/*06*/	uint16_t	version;
/*08*/	char		cipher_name[SZ_CIPHER_NAME];
/*28*/	char		cipher_mode[SZ_CIPHER_MODE];
/*48*/	char		hash_spec[SZ_HASH_SPEC];
/*68*/	uint32_t	off_payload;	// sector of bulk data
/*6c*/	uint32_t	sz_key;		// key bytes

	// PBKDF2 params
/*70*/	uint8_t		mk_digest[SZ_MK_DIGEST];
/*84*/	uint8_t		mk_salt[SZ_SALT];
/*a4*/	uint32_t	mk_iterations;

/*a8*/	char		uuid_part[SZ_UUID];
/*d0*/	struct key	keys[NUM_KEYS];
// 250 (592 bytes)
};

enum hash_type {
	HT_MD5,
	HT_RIPEMD160,
	HT_SHA1,
	HT_SHA224,
	HT_SHA256,
	HT_SHA384,
	HT_SHA512,
	HT_UNDEFINED
};

// the main purpose of this structure is to extend the header with cached
// values for the hash/cipher specs
struct header {
	boost::scoped_ptr<struct phdr1>	hdr;
	boost::scoped_array<uint8_t>	master_key;
	enum hash_type			hash_type;
};


// switch to/from BE
inline void	endian_switch(struct phdr1 *, bool process_keys);
inline void	endian_switch(struct key *);


void	add_password(struct header *, const std::string &);
void	initialize(struct header *, uint32_t, const std::string &,
	    const std::string &, const std::string &, uint32_t, size_t);
void	read_key(struct header *, const std::string &);
void	revoke_password(struct header *, size_t);

}

#include "luks_private.hpp"

#endif
