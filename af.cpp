/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <arpa/inet.h>

#include <algorithm>

#include <openssl/rand.h>

#include "af.hpp"
#include "errors.hpp"
#include "hash.hpp"
#include "util.hpp"

namespace fluks {
namespace {

void	compute_d(const uint8_t *, size_t, unsigned, enum hash_type,
	    uint8_t *);
void	hash1(const uint8_t *, size_t, enum hash_type, uint8_t *);
void	hash2(const uint8_t *, size_t, enum hash_type, uint8_t *);

// compute the last d_i value
void
compute_d(const uint8_t *s, size_t sz, unsigned stripes,
    enum hash_type type, uint8_t *final_d)
{
	uint8_t d[sz];

	uint8_t *d_odd;
	uint8_t *d_even;

	// last to compute is d_{stripes-1}, which should be stored
	// at final_d
	
	if (stripes % 2) {
		// (stripes - 1) is even
		d_odd = d;
		d_even = final_d;
	} else {
		d_odd = final_d;
		d_even = d;
	}

	std::fill(d_even, d_even + sz, 0);

	for (size_t i = 1; i < stripes - 1; i++) {
		// d_even ^= i'th stripe
		xor_bufs(d_even, s + i * sz, sz, d_even);
		// d_odd = H(d_even)
		hash1(d_even, sz, type, d_odd);

		if (++i == stripes - 1) return;

		// d_odd ^= i'th stripe
		xor_bufs(d_odd, s + i * sz, sz, d_odd);
		// d_even = H(d_odd)
		hash1(d_odd, sz, type, d_even);
	}
	return;
}

// basically a one-way hash where ||in|| = ||out||; defined in the LUKS spec;
// this is the *improper* version used in LUKSv1
void
hash1(const uint8_t *in, size_t sz, enum hash_type type, uint8_t *out)
{
	std::tr1::shared_ptr<Hash_function> hashfn(
	    Hash_function::create(type));

	uint32_t	iv;
	// the wording in LUKS is bad; it should read 'Digest Size'
	size_t		sz_blk = hashfn->digest_size();
	size_t		whole = sz / sz_blk;
	size_t		left = sz % sz_blk;

	for (size_t i = 0; i < whole; i++) {
		// compute hash of next block; append digest to output 

		hashfn->init();
		// prefix with an IV
		iv = htonl(i);
		hashfn->add(reinterpret_cast<uint8_t *>(&iv), 4);
		hashfn->add(in, sz_blk);
		hashfn->end(out);

		in += sz_blk;
		out += sz_blk;
	}

	if (left) {
		// compute hash of rest of data; append first (left) bytes
		// of hash to output

		uint8_t full[sz_blk];
		hashfn->init();
		// prefix with an IV
		iv = htonl(whole);
		hashfn->add(reinterpret_cast<uint8_t *>(&iv), 4);
		hashfn->add(in, left);
		hashfn->end(full);

		std::copy(full, full + left, out);
	}
}

// basically a one-way hash where ||in|| = ||out||; defined in the LUKS spec;
// this is the *proper* version *not* used in LUKSv1
void
hash2(const uint8_t *in, size_t sz, enum hash_type type, uint8_t *out)
{
	std::tr1::shared_ptr<Hash_function> hashfn(
	    Hash_function::create(type));

	uint32_t	iv;
	// the wording in LUKS is bad; it should read 'Digest Size'
	size_t		sz_blk = hashfn->digest_size();
	size_t		whole = sz / sz_blk;
	size_t		left = sz % sz_blk;

	for (size_t i = 0; i < whole; i++) {
		// compute hash of next block; append digest to output 

		hashfn->init();
		// prefix with an IV
		iv = htonl(i);
		hashfn->add(reinterpret_cast<uint8_t *>(&iv), 4);
		// key difference between hash1() and hash2() [part un]:
		hashfn->add(in, sz);
		hashfn->end(out);

		out += sz_blk;
	}

	if (left) {
		// compute hash of rest of data; append first (left) bytes
		// of hash to output

		uint8_t full[sz_blk];
		hashfn->init();
		// prefix with an IV
		iv = htonl(whole);
		hashfn->add(reinterpret_cast<uint8_t *>(&iv), 4);
		// key difference between hash1() and hash2() [part deux]:
		hashfn->add(in, sz);
		hashfn->end(full);

		std::copy(full, full + left, out);
	}
}

} // end anonymous namespace
}

void
fluks::af_split(const uint8_t *in, size_t sz, size_t stripes,
    enum hash_type type, uint8_t *out)
{
	Assert(type != HT_UNDEFINED, "undefined hash in af_split()");

	uint8_t d[sz];
	if (!RAND_bytes(out, sz * (stripes - 1)))
		throw Ssl_error();

	// d_0 = 0
	// d_k = H( d_{k-1} ^ s_k )
	// s_n = d_{n-1} ^ D
	compute_d(out, sz, stripes, type, d);
	xor_bufs(d, in, sz, out + sz * (stripes - 1));
}

void
fluks::af_merge(const uint8_t *in, size_t sz, size_t stripes,
    enum hash_type type, uint8_t *out)
{
	Assert(type != HT_UNDEFINED, "undefined hash in af_merge()");

	uint8_t d[sz];

	// d_0 = 0
	// d_k = H( d_{k-1} ^ s_k )
	// D = d_{n-1} ^ s_n
	compute_d(in, sz, stripes, type, d);
	xor_bufs(d, in + sz * (stripes - 1), sz, out);
}
