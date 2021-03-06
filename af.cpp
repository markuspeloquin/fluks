/* Copyright (c) 2009-2010, Markus Peloquin <markus@cs.wisc.edu>
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
#include <memory>

#include <openssl/rand.h>

#include "af.hpp"
#include "errors.hpp"
#include "hash.hpp"
#include "util.hpp"

namespace fluks {
namespace {

void	compute_last_d(const uint8_t *, size_t, int, hash_type, uint8_t *);
void	hash(const uint8_t *, size_t, hash_type, uint8_t *);

// compute d_{n-1}: the last d_i value
void
compute_last_d(const uint8_t *s, size_t sz, int stripes, hash_type type,
    uint8_t *d_f) {
	std::unique_ptr<uint8_t[]> d{new uint8_t[sz]};
	uint8_t *d_0; // d_{i+0}
	uint8_t *d_1; // d_{i+1}

	Assert(stripes > 0, "'stripes' must be positive");

	// last to compute is d_{stripes-1}, which should be stored at d_f

	if (stripes % 2) {
		// (stripes - 1) is even
		d_0 = d_f;
		d_1 = d.get();
	} else {
		d_0 = d.get();
		d_1 = d_f;
	}

	std::fill(d_0, d_0 + sz, 0);

	for (int i = 1; i < stripes; i++) {
		// d_0 ^= i'th stripe
		xor_bufs(d_0, s, sz, d_0);
		// d_1 = H(d_0)
		hash(d_0, sz, type, d_1);
		s += sz;

		if (++i == stripes) break;

		// d_1 ^= i'th stripe
		xor_bufs(d_1, s, sz, d_1);
		// d_0 = H(d_1)
		hash(d_1, sz, type, d_0);
		s += sz;
	}
}

// basically a one-way hash where ||in|| = ||out||; defined in the LUKS spec
void
hash(const uint8_t *in, size_t sz, hash_type type, uint8_t *out) {
	std::shared_ptr<Hash_function> hashfn(Hash_function::create(type));

	uint32_t	iv;
	// the wording in LUKS is bad; it should read 'Digest Size'
	size_t		sz_blk = hashfn->traits()->digest_size;
	size_t		whole = sz / sz_blk;
	size_t		left = sz % sz_blk;

	for (size_t i = 0; i < whole; i++) {
		// compute hash of next block; append digest to output

		hashfn->init();
		// prefix with an IV
		iv = fluks_htobe32(i);
		hashfn->add(reinterpret_cast<uint8_t *>(&iv), 4);
		hashfn->add(in, sz_blk);
		hashfn->end(out);

		in += sz_blk;
		out += sz_blk;
	}

	if (left) {
		// compute hash of rest of data; append first (left) bytes
		// of hash to output

		std::unique_ptr<uint8_t[]> full{new uint8_t[sz_blk]};
		hashfn->init();
		// prefix with an IV
		iv = fluks_htobe32(whole);
		hashfn->add(reinterpret_cast<uint8_t *>(&iv), 4);
		hashfn->add(in, left);
		hashfn->end(full.get());

		std::copy(full.get(), full.get() + left, out);
	}
}

} // end anonymous namespace
}

void
fluks::af_split(const uint8_t *in, size_t sz, size_t stripes, hash_type type,
    uint8_t *out) {
	Assert(type != hash_type::UNDEFINED, "undefined hash in af_split()");

	std::unique_ptr<uint8_t[]> d{new uint8_t[sz]};
#ifdef DEBUG
	// for valgrind
	std::fill(out, out + sz * (stripes - 1), 0);
#endif
	if (!RAND_bytes(out, sz * (stripes - 1)))
		throw Ssl_error();

	// d_0 = 0
	// d_k = H( d_{k-1} ^ s_k )
	// s_n = d_{n-1} ^ D
	compute_last_d(out, sz, stripes, type, d.get());
	xor_bufs(d.get(), in, sz, out + sz * (stripes - 1));
}

void
fluks::af_merge(const uint8_t *in, size_t sz, size_t stripes, hash_type type,
    uint8_t *out) {
	Assert(type != hash_type::UNDEFINED, "undefined hash in af_merge()");

	std::unique_ptr<uint8_t[]> d{new uint8_t[sz]};

	// d_0 = 0
	// d_k = H( d_{k-1} ^ s_k )
	// D = d_{n-1} ^ s_n
	compute_last_d(in, sz, static_cast<int>(stripes), type, d.get());
	xor_bufs(d.get(), in + sz * (stripes - 1), sz, out);
}
