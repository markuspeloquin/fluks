/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
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

#include <algorithm>

#include "hmac.hpp"
#include "pbkdf2.hpp"
#include "support.hpp"
#include "util.hpp"

namespace fluks {
namespace {

// Function F() in part 3 of the PBKDF2 algorithm [RFC 2898]
inline void
pbkdf2_f(Hmac_function *hmacfn,
    const uint8_t *passwd, uint32_t sz_passwd,
    const uint8_t *salt, size_t sz_salt,
    uint32_t iterations, uint32_t index, uint8_t *result)
{
	// 3.
	// As defined:
	//
	// P: password
	// S: salt
	// c: iteration count
	// i: index [1,l]
	//
	// INT(i): 32-bit big-endian encoding of i
	//
	// U_1 = PRF(P, S . INT(i))
	// U_j = PRF(P, U_{j-1})
	// (as in some circles, '.' means concatenate)
	//
	// F(P, S, c, i) = XOR for j=[1,c] of { U_j }
	//
	// I instead use 0-indexing (index: [0,l), j: [0,c)).

	uint8_t u[hmacfn->traits()->digest_size];

	// '+ 1': switch from 0-indexing to 1-indexing
	index = htobe32(index + 1);

	// compute U_0
	hmacfn->init(passwd, sz_passwd);
	hmacfn->add(salt, sz_salt);
	hmacfn->add(reinterpret_cast<uint8_t *>(&index), 4);
	hmacfn->end(u);

	std::copy(u, u + sizeof(u), result);

	for (uint32_t i = 1; i < iterations; i++) {
		// compute U_i
		hmacfn->init(passwd, sz_passwd);
		hmacfn->add(u, sizeof(u));
		hmacfn->end(u);

		xor_bufs(u, result, sizeof(u), result);
	}
}

}} // end anonymous namespace

// Password-Based Key Derivation Function, version 2 (from PKCS #5 v2.0)
void
fluks::pbkdf2(hash_type type,
    const uint8_t *in, uint32_t sz_in,
    const uint8_t *salt, size_t sz_salt,
    uint32_t iterations,
    uint8_t *derived_key, uint32_t sz_key)
    noexcept(false)
{
	if (type == hash_type::UNDEFINED)
		throw Bad_spec("PBKDF2 needs a hash function");
	uint32_t sz_hash = Hash_traits::traits(type)->digest_size;

	// 1.
	// If dkLen > (2^32 - 1) * hLen, stop
	if (sz_key > static_cast<uint64_t>(0xffffffff) * sz_hash)
		throw std::length_error(
		    "PBKDF2 derived key too long");

	// 2.
	// In the spec:
	//
	// l = ceil(sz_key / hash_size(type))
	//	(number of blocks, including final partial block)
	// r = dkLen - (l - 1) * hLen
	//	(bytes in final partial block)
	//
	// I define blocks and partial in a more useful way.
	uint32_t blocks = sz_key / sz_hash;
	uint32_t partial = sz_key % sz_hash;

	// 3.
	// T_i = F(P, S, c, i) for i in [1,l]
	//
	// I instead use 0-indexing. I combine this step with (4).

	// 4.
	// Concatenate all T_i. The first dkLen bytes is the derived key.
	// Iterate over all but the partial block.
	std::shared_ptr<Hmac_function> hmacfn = Hmac_function::create(type);
	for (uint32_t i = 0; i < blocks; i++)
		pbkdf2_f(hmacfn.get(), in, sz_in, salt, sz_salt, iterations,
		    i, derived_key + i * sz_hash);

	if (partial) {
		uint8_t buf_partial[sz_hash];
		pbkdf2_f(hmacfn.get(), in, sz_in, salt, sz_salt, iterations,
		    blocks, buf_partial);
		std::copy(buf_partial, buf_partial + partial,
		    derived_key + blocks * sz_hash);
	}
}
