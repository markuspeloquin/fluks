#include <arpa/inet.h>

#include <algorithm>

#include <openssl/rand.h>

#include "af.hpp"
#include "hash.hpp"
#include "util.hpp"

namespace {

void	compute_d(const uint8_t *, size_t, unsigned, enum luks::hash_type,
	    uint8_t *);
void	hash1(const uint8_t *, size_t, enum luks::hash_type, uint8_t *);
void	hash2(const uint8_t *, size_t, enum luks::hash_type, uint8_t *);

// compute the last d_i value
void
compute_d(const uint8_t *s, size_t sz, unsigned stripes,
    enum luks::hash_type type, uint8_t *final_d)
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
		// d_odd ^= i'th stripe
		luks::xor_bufs(d_odd, s + i * sz, sz, d_odd);
		// d_even = H(d_odd)
		hash1(d_odd, sz, type, d_even);

		if (++i == stripes - 1) return;

		// d_even ^= i'th stripe
		luks::xor_bufs(d_even, s + i * sz, sz, d_even);
		// d_odd = H(d_even)
		hash1(d_even, sz, type, d_odd);
	}
	return;
}

// basically a one-way hash where ||in|| = ||out||; defined in the LUKS spec;
// this is the *improper* version used in LUKSv1
void
hash1(const uint8_t *in, size_t sz, enum luks::hash_type type, uint8_t *out)
{
	std::tr1::shared_ptr<luks::Hash_function> hashfn(
	    luks::Hash_function::create(type));

	uint32_t	initial;
	size_t		whole = sz / hashfn->digest_size();
	size_t		left = sz % hashfn->digest_size();

	for (size_t i = 0; i < whole; i++) {
		// compute hash of next block; append digest to output 

		hashfn->init();
		// prefix with an IV (initial value)
		initial = htonl(i);
		hashfn->add(reinterpret_cast<uint8_t *>(&initial), 4);
		hashfn->add(in, hashfn->digest_size());
		hashfn->end(out);

		in += hashfn->digest_size();
		out += hashfn->digest_size();
	}

	if (left) {
		// compute hash of rest of data; append first (left) bytes
		// of hash to output

		uint8_t full[hashfn->digest_size()];
		hashfn->init();
		// prefix with an IV (initial value)
		initial = htonl(whole);
		hashfn->add(reinterpret_cast<uint8_t *>(&initial), 4);
		hashfn->add(in, left);
		hashfn->end(full);

		std::copy(full, full + left, out);
	}
}

// basically a one-way hash where ||in|| = ||out||; defined in the LUKS spec;
// this is the *proper* version *not* used in LUKSv1
void
hash2(const uint8_t *in, size_t sz, enum luks::hash_type type, uint8_t *out)
{
	std::tr1::shared_ptr<luks::Hash_function> hashfn(
	    luks::Hash_function::create(type));

	uint32_t	initial;
	size_t		whole = sz / hashfn->digest_size();
	size_t		left = sz % hashfn->digest_size();

	for (size_t i = 0; i < whole; i++) {
		// compute hash of next block; append digest to output 

		hashfn->init();
		// prefix with an IV (initial value)
		initial = htonl(i);
		hashfn->add(reinterpret_cast<uint8_t *>(&initial), 4);
		// key difference between hash1() and hash2() [part un]:
		hashfn->add(in, sz);
		hashfn->end(out);

		out += hashfn->digest_size();
	}

	if (left) {
		// compute hash of rest of data; append first (left) bytes
		// of hash to output

		uint8_t full[hashfn->digest_size()];
		hashfn->init();
		// prefix with an IV (initial value)
		initial = htonl(whole);
		hashfn->add(reinterpret_cast<uint8_t *>(&initial), 4);
		// key difference between hash1() and hash2() [part deux]:
		hashfn->add(in, sz);
		hashfn->end(full);

		std::copy(full, full + left, out);
	}
}

} // end anonymous namespace

void
luks::af_split(const uint8_t *in, size_t sz, size_t stripes,
    enum hash_type type, uint8_t *out)
{
	if (type == HT_UNDEFINED) return;

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
luks::af_merge(const uint8_t *in, size_t sz, size_t stripes,
    enum hash_type type, uint8_t *out)
{
	if (type == HT_UNDEFINED) return;

	uint8_t d[sz];

	// d_0 = 0
	// d_k = H( d_{k-1} ^ s_k )
	// D = d_{n-1} ^ s_n
	compute_d(in, sz, stripes, type, d);
	xor_bufs(d, in + sz * (stripes - 1), sz, out);
}
