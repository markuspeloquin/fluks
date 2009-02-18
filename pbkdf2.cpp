#include <cstdlib>

#include "hash.hpp"
#include "pbkdf2.hpp"
#include "util.hpp"

namespace luks {
namespace {

inline void	pbkdf2_f(enum hash_type, const uint8_t *, uint32_t,
		    const uint8_t[SZ_SALT], uint32_t, uint32_t, uint8_t *);

// function F() of part 3 of the PBKDF2 definition in PKCS #5 v2.0, and
// described in pbkdf2() below
inline void
pbkdf2_f(enum hash_type type, const uint8_t *in, uint32_t sz_in,
    const uint8_t salt[SZ_SALT], uint32_t iterations, uint32_t index,
    uint8_t *result)
{
	std::tr1::shared_ptr<Hmac_function> hmacfn =
	    Hmac_function::create(type);

	uint8_t u[hmacfn->length()];

	// I use indices starting at 0, but PBKDF2 starts at 1
	index = htonl(index + 1);

	// compute U_0 (PBKDF2's U_1)
	hmacfn->init(in, sz_in);
	hmacfn->add(salt, SZ_SALT);
	hmacfn->add(reinterpret_cast<uint8_t *>(&index), 4);
	hmacfn->end(u, sizeof(u));

	memcpy(result, u, sizeof(u));

	for (uint32_t i = 1; i < iterations; i++) {
		// compute U_i
		hmacfn->init(in, sz_in);
		hmacfn->add(u, sizeof(u));
		hmacfn->end(u, sizeof(u));

		xor_bufs(u, result, sizeof(u), result);
	}
}

}} // end anonymous namespace

// Password-Based Key Derivation Function, version 2 (from PKCS #5 v2.0)
void
luks::pbkdf2(enum hash_type type, const uint8_t *in, uint32_t sz_in,
    const uint8_t salt[SZ_SALT], uint32_t iterations, uint8_t *derived_key,
    uint32_t sz_key)
	throw (std::length_error)
{
	uint32_t sz_hash = hash_size(type);

	// 1.
	// If dkLen > (2^32 - 1) * hLen, stop
	if (sz_key > static_cast<uint64_t>(0xffffffff) * sz_hash)
		throw std::length_error(
		    "PBKDF2 derived key too long");

	// 2.
	// l = ceil(sz_key / hash_size(type))
	//	(number of blocks, including final partial block)
	// r = dkLen - (l - 1) * hLen
	//	(bytes in final partial block)
	//
	// I define blocks and partial differently.
	uint32_t blocks = sz_key / sz_hash;
	uint32_t partial = sz_key % sz_hash;

	// 3.
	// (note that I start indices at 0 instead of 1)
	// P: password
	// S: salt
	// c: iteration count
	// INT(i): 32-bit big-endian encoding of i
	// U_j defined on j=[0,c):
	//	U_0 = PRF(P, S . INT(i))
	//	U_j = PRF(P, U_{j-1})
	//	(PRF: underlying pseudo-random function)
	//	(as in some circles, '.' means concatenate)
	// F(P, S, c, i) = XOR for j=[0,c) of { U_j }
	// T_i defined on i=[0,l):
	//	F(P, S, c, i)
	//
	// ... now compute all T_i, though this gets combined with (4) in
	// the code

	// 4.
	// Concatenate all T_i.  The first dkLen bytes is the derived key.
	// Iterate over all but the partial block
	for (uint32_t i = 0; i < blocks; i++)
		pbkdf2_f(type, in, sz_in, salt, iterations, i,
		    derived_key + i * sz_hash);

	if (partial) {
		uint8_t buf_partial[sz_hash];
		pbkdf2_f(type, in, sz_in, salt, iterations, blocks,
		    buf_partial);
		memcpy(derived_key + blocks * sz_hash, buf_partial, partial);
	}
}
