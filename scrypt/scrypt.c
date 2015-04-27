#include <assert.h>
#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <stdio.h>

#include <openssl/sha.h>

#include "scrypt.h"

// scrypt implementation with no extranneous copies!
//
// PBKDF2 implementation was simplified for iterations=1
//
// HMAC was simplified for its limited use within PBKDF2, both in terms of
// saving some intermediate state and avoiding all the overhead within
// OpenSSL's function calls and allocations (who has time to check return
// values?)

struct hmac_sha256_ctx {
	uint8_t outerkey[SHA256_CBLOCK];
	uint8_t innerkey[SHA256_CBLOCK];
};

// untested:
static void	block_mix_salsa208(unsigned, const uint8_t *, uint8_t *);
void		hmac_sha256_init(struct hmac_sha256_ctx *, const uint8_t *,
		    size_t);
static void	hmac_sha256_pbkdf2init_start(
		    const struct hmac_sha256_ctx *, SHA256_CTX *,
		    const uint8_t *, size_t);
static void	hmac_sha256_pbkdf2init_finalize(
		    const struct hmac_sha256_ctx *, const SHA256_CTX *,
		    uint32_t, uint8_t *);
// untested:
static inline unsigned
		integerify(const uint8_t *, unsigned, unsigned);
void		pbkdf2_hmac_sha256(const struct hmac_sha256_ctx *,
		    const uint8_t *, size_t, uint8_t *, uint64_t);
// untested:
static void	salsa20_8_inplace(uint8_t *);
// untested:
static void	smix(unsigned, const uint8_t *, unsigned, uint8_t *);

// set up outerkey and innerkey for repeated reuse
void
hmac_sha256_init(struct hmac_sha256_ctx *ctx, const uint8_t *passwd,
    size_t passwd_len)
{
	if (passwd_len > SHA256_CBLOCK) {
		SHA256_CTX pwctx;
		SHA256_Init(&pwctx);
		SHA256_Update(&pwctx, passwd, passwd_len);
		SHA256_Final(ctx->outerkey, &pwctx);
		for (size_t i = SHA256_DIGEST_LENGTH; i < SHA256_CBLOCK; i++)
			ctx->outerkey[i] = 0;
	} else {
		memcpy(ctx->outerkey, passwd, passwd_len);
		for (size_t i = passwd_len; i < SHA256_CBLOCK; i++)
			ctx->outerkey[i] = 0;
	}
	uint32_t *inner32 = (uint32_t *)ctx->innerkey;
	uint32_t *outer32 = (uint32_t *)ctx->outerkey;
	for (size_t i = 0; i < SHA_LBLOCK; i++) {
		*inner32++ = *outer32 ^ 0x36363636;
		*outer32++ ^= 0x5c5c5c5c;
	}
}

static void
hmac_sha256_pbkdf2init_start(const struct hmac_sha256_ctx *ctx,
    SHA256_CTX *sha, const uint8_t *salt, size_t salt_len)
{
	SHA256_Init(sha);
	SHA256_Update(sha, ctx->innerkey, SHA256_CBLOCK);
	SHA256_Update(sha, salt, salt_len);
}

static void
hmac_sha256_pbkdf2init_finalize(const struct hmac_sha256_ctx *ctx,
    const SHA256_CTX *sha_base, uint32_t iter, uint8_t *out)
{
	SHA256_CTX sha;
	memcpy(&sha, sha_base, sizeof(SHA256_CTX));
	iter = htobe32(iter);
	SHA256_Update(&sha, &iter, sizeof(iter));

	uint8_t innerbuf[SHA256_DIGEST_LENGTH];
	SHA256_Final(innerbuf, &sha);

	SHA256_Init(&sha);
	SHA256_Update(&sha, ctx->outerkey, SHA256_CBLOCK);
	SHA256_Update(&sha, innerbuf, SHA256_DIGEST_LENGTH);
	SHA256_Final(out, &sha);
}

// PBKDF2 with HMAC(SHA256) and one iteration
void
pbkdf2_hmac_sha256(const struct hmac_sha256_ctx *ctx,
    const uint8_t *salt, size_t salt_len, uint8_t *out, uint64_t out_len)
{
	const unsigned hlen = SHA256_DIGEST_LENGTH;

	// "derived key too long"
	assert(out_len <= (uint32_t)-1 * (uint64_t)hlen);

	// prevents underflow (l-1) in loop; also, the calculation for r only
	// works if out_len > 0
	if (!out_len) return;

	uint32_t l = (out_len + hlen - 1) / hlen;
	uint64_t r = out_len - (l - 1) * hlen;

	SHA256_CTX init_sha_ctx;
	hmac_sha256_pbkdf2init_start(ctx, &init_sha_ctx, salt, salt_len);

	for (uint32_t i = 0; i < l-1; i++) {
		hmac_sha256_pbkdf2init_finalize(ctx, &init_sha_ctx, i+1,
		    out);
		out += hlen;
	}

	if (r) {
		uint8_t finalblock[hlen];
		hmac_sha256_pbkdf2init_finalize(ctx, &init_sha_ctx, l,
		    finalblock);
		for (size_t i = 0; i < r; i++)
			out[i] = finalblock[i];
	} else
		hmac_sha256_pbkdf2init_finalize(ctx, &init_sha_ctx, l, out);
}

#define SALSA_BLOCK 64
#define SALSA_WORDS (SALSA_BLOCK/4)

#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
static void
salsa20_8_inplace(uint8_t block[SALSA_BLOCK])
{
	uint32_t *block32 = (uint32_t *)block;

	uint32_t x[SALSA_WORDS];
	for (int i = 0; i < SALSA_WORDS; ++i)
		x[i] = block32[i] = le32toh(block32[i]);
	for (int i = 8; i > 0; i -= 2) {
		x[ 4] ^= R(x[ 0]+x[12], 7); x[ 8] ^= R(x[ 4]+x[ 0], 9);
		x[12] ^= R(x[ 8]+x[ 4],13); x[ 0] ^= R(x[12]+x[ 8],18);
		x[ 9] ^= R(x[ 5]+x[ 1], 7); x[13] ^= R(x[ 9]+x[ 5], 9);
		x[ 1] ^= R(x[13]+x[ 9],13); x[ 5] ^= R(x[ 1]+x[13],18);
		x[14] ^= R(x[10]+x[ 6], 7); x[ 2] ^= R(x[14]+x[10], 9);
		x[ 6] ^= R(x[ 2]+x[14],13); x[10] ^= R(x[ 6]+x[ 2],18);
		x[ 3] ^= R(x[15]+x[11], 7); x[ 7] ^= R(x[ 3]+x[15], 9);
		x[11] ^= R(x[ 7]+x[ 3],13); x[15] ^= R(x[11]+x[ 7],18);
		x[ 1] ^= R(x[ 0]+x[ 3], 7); x[ 2] ^= R(x[ 1]+x[ 0], 9);
		x[ 3] ^= R(x[ 2]+x[ 1],13); x[ 0] ^= R(x[ 3]+x[ 2],18);
		x[ 6] ^= R(x[ 5]+x[ 4], 7); x[ 7] ^= R(x[ 6]+x[ 5], 9);
		x[ 4] ^= R(x[ 7]+x[ 6],13); x[ 5] ^= R(x[ 4]+x[ 7],18);
		x[11] ^= R(x[10]+x[ 9], 7); x[ 8] ^= R(x[11]+x[10], 9);
		x[ 9] ^= R(x[ 8]+x[11],13); x[10] ^= R(x[ 9]+x[ 8],18);
		x[12] ^= R(x[15]+x[14], 7); x[13] ^= R(x[12]+x[15], 9);
		x[14] ^= R(x[13]+x[12],13); x[15] ^= R(x[14]+x[13],18);
	}
	for (int i = 0; i < SALSA_WORDS; ++i)
		block32[i] = htole32(block32[i] + x[i]);
}
#undef R

static void
block_mix_salsa208(unsigned r, const uint8_t *in, uint8_t *out)
{
	// unrolled loop operations:
	// Y_0 <- H(B_0 ^ B_{2r-1})
	// Y_1 <- H(B_1 ^ Y_0)
	// Y_2 <- H(B_2 ^ Y_1)
	// ...
	// Y_{2r-1} <- B_{2r-1} ^ H(Y_{2r-2})

	// initially, B_{2r-1}; in loop, it will be set to Y_0, Y_1, ...
	const uint8_t *prev = in + (2*r-1) * SALSA_BLOCK;
	for (unsigned i = 0; i < 2*r; i++) {
		for (size_t j = 0; j < SALSA_BLOCK; j++)
			out[j] = prev[j] ^ in[j];
		in += SALSA_BLOCK;

		salsa20_8_inplace(out);
		prev = out;
		out += SALSA_BLOCK;
	}
}

static inline unsigned
integerify(const uint8_t *block, unsigned r, unsigned mod)
{
	const uint32_t *block32 = (const uint32_t *)block;
	uint32_t last = htole32(block32[(2 * r - 1) * SALSA_WORDS]);
	return last & (mod-1);
}

static void
smix(unsigned r, const uint8_t *in, unsigned work_metric, uint8_t *out)
{
	const size_t BLOCK = 2 * r * SALSA_BLOCK;

	// extra block is V_N, which is just storage for the final X value
	// in the first loop
	uint8_t v[BLOCK * (work_metric + 1)];
	uint8_t *out_v;
	uint8_t *prev; // X

	// first loop, unrolled:
	// V_0 <- B
	// V_1 <- H(V_0)
	// V_2 <- H(V_2)
	// ...
	// V_{N-1} <- H(V_{N-2})
	// X <- H(V_{N-1})

	// V_0 <- B
	for (size_t i = 0; i < SALSA_BLOCK; i++)
		v[i] = in[i];
	prev = v;
	out_v = v + BLOCK;
	for (unsigned i = 1; i <= work_metric; i++) {
		// V_{i} <- H(V_{i-1})
		// final iteration:
		// V_{N} <- H(V_{N-1}), where V_{N} is just storage for the
		// final X
		block_mix_salsa208(r, prev, out_v);
		prev = out_v;
		out_v += BLOCK;
	}

	// the cost to compute an entry plus lookup times is less than
	// computing (v + BLOCK * j) each iteration below
	uint8_t *table[work_metric];
	table[0] = v;
	for (unsigned i = 1; i < work_metric; i++)
		table[i] = table[i-1] + BLOCK;

	for (unsigned i = 0; i < work_metric; i++) {
		unsigned j = integerify(prev, r, work_metric);
		uint8_t *block = table[j];
		// X ^= block
		for (size_t k; k < SALSA_BLOCK; k++)
			prev[k] ^= block[k];
		// (X's location changes the first time through this loop)
		// X <- H(X)
		block_mix_salsa208(r, prev, out);
		prev = out;
	}
	// final X already copied to 'out' by block_mix_salsa208()
}

void
scrypt(const uint8_t *passwd, size_t passwd_len,
    const uint8_t *salt, size_t salt_len,
    unsigned cpu_mem_cost, unsigned r, unsigned parallelization,
    uint8_t *dk, size_t dk_len)
{
	// cpu_mem_cost must be a power of two and at most 32 bits
	assert(((cpu_mem_cost - 1) & cpu_mem_cost) == 0);
	assert(cpu_mem_cost < (uint32_t)-1);

	const size_t SMIX_BLOCK = 2 * r * SALSA_BLOCK;

	assert(parallelization <=
	    ((uint32_t)-1) * SHA256_DIGEST_LENGTH / SMIX_BLOCK);

	// dk_len <= (2^32-1) * 2^6
	assert(dk_len <= ((uint32_t)-1) * SHA256_DIGEST_LENGTH);

	struct hmac_sha256_ctx ctx;
	hmac_sha256_init(&ctx, passwd, passwd_len);

	// each B_i is the length of SMIX_BLOCK
	uint8_t B[parallelization * SMIX_BLOCK];
	pbkdf2_hmac_sha256(&ctx, salt, salt_len, B, sizeof(B));
	for (uint8_t *b_i = B; b_i - B < sizeof(B); b_i += SALSA_BLOCK)
		smix(r, b_i, cpu_mem_cost, b_i);
	pbkdf2_hmac_sha256(&ctx, B, sizeof(B), dk, dk_len);
}
