/* The following code was written by Drew Csillag. It was modified so as to
 * not memcpy functions and subsequently modify them. That's too much voodoo
 * for my tastes. Also, macros are used less, malloc()/free() removed from the
 * key schedule, and the code was generally cleaned up. */

#include <string.h>

#include "crypto_ops.h"
#include "endian.h"
#include "twofish.h"
#include "twofish_tables.h"

const uint32_t RHO = 0x01010101UL;
const uint16_t RS_MOD = 0x14D;

/* get byte N of x, where 0 is the least significant byte */
#define b_n(x, N) ((uint8_t)((x) >> (N)*8))

/* just casting to byte (instead of masking with 0xFF saves *tons* of clocks
 * (around 50) */
#define b0(x) ((uint8_t)((x)      ))
#define b1(x) ((uint8_t)((x) >>  8))
#define b2(x) ((uint8_t)((x) >> 16))
#define b3(x)           ((x) >> 24)

/* multiply two polynomials represented as uint32_t's, actually called with
 * uint8_t'S, but since I'm not really going to too much work to optimize key
 * setup (since raw encryption speed is what I'm after), big deal. */
static inline uint32_t
poly_mult(uint32_t a, uint32_t b)
{
	uint32_t	t = 0;
	while (a) {
		if (a & 1) t ^= b;
		b <<= 1;
		a >>= 1;
	}
	return t;
}

/* take the polynomial t and return the t % modulus in GF(256) */
static inline uint32_t
gf_mod(uint32_t t, uint32_t modulus)
{
	modulus <<= 7;
	for (uint8_t i = 0; i < 8; i++) {
		uint32_t tt = t ^ modulus;
		if (tt < t) t = tt;
		modulus >>= 1;
	}
	return t;
}

/* multiply a and b and return the modulus */
static inline uint32_t
gf_mult(uint32_t a, uint32_t b, uint32_t modulus)
{
	return gf_mod(poly_mult(a, b), modulus);
}

/* return a uint32_t containing the result of multiplying the RS Code matrix
 * by the sd matrix */
static uint32_t
rs_mat_mult(uint8_t sd[8])
{
	union {
		uint8_t		buf[4];
		uint32_t	word;
	} result;

	for (uint8_t j = 0; j < 4; j++) {
		uint8_t t = 0;
		for (uint8_t k = 0; k < 8; k++)
			t ^= gf_mult(rs[j][k], sd[k], RS_MOD);
		result.buf[j ^ 3] = t;
	}
	return be32toh(result.word);
}

/* the Zero-keyed h function (used by the key setup routine) */
static uint32_t
tf_h(uint32_t X, uint32_t L[4], uint8_t k)
{
	uint8_t		y0,y1,y2,y3;
	uint8_t		z0,z1,z2,z3;
	y0 = b0(X);
	y1 = b1(X);
	y2 = b2(X);
	y3 = b3(X);

	switch(k) {
	case 4:
		y0 = q1[y0] ^ b0(L[3]);
		y1 = q0[y1] ^ b1(L[3]);
		y2 = q0[y2] ^ b2(L[3]);
		y3 = q1[y3] ^ b3(L[3]);
	case 3:
		y0 = q1[y0] ^ b0(L[2]);
		y1 = q1[y1] ^ b1(L[2]);
		y2 = q0[y2] ^ b2(L[2]);
		y3 = q0[y3] ^ b3(L[2]);
	case 2:
		y0 = q1[  q0 [ q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
		y1 = q0[  q0 [ q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
		y2 = q1[  q1 [ q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
		y3 = q0[  q1 [ q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
	}

	/* inline the MDS matrix multiply */
	z0 = multEF[y0] ^ y1         ^ multEF[y2] ^ mult5B[y3];
	z1 = multEF[y0] ^ mult5B[y1] ^ y2         ^ multEF[y3];
	z2 = mult5B[y0] ^ multEF[y1] ^ multEF[y2] ^ y3;
	z3 = y0         ^ multEF[y1] ^ mult5B[y2] ^ mult5B[y3];

	return z0 << 24 | z1 << 16 | z2 << 8 | z3;
}

/* given the Sbox keys, create the fully keyed QF */
static void
full_key(uint32_t L[4], uint8_t word_pairs, uint32_t QF[4][256])
{
	uint8_t		y0,y1,y2,y3;
	uint8_t		i = 0;

	/* for all input values to the Q permutations */
	do {
		/* run the Q permutations */
		y0 = y1 = y2 = y3 = i;
		switch (word_pairs) {
		case 4:
			y0 = q1[y0] ^ b0(L[3]);
			y1 = q0[y1] ^ b1(L[3]);
			y2 = q0[y2] ^ b2(L[3]);
			y3 = q1[y3] ^ b3(L[3]);
		case 3:
			y0 = q1[y0] ^ b0(L[2]);
			y1 = q1[y1] ^ b1(L[2]);
			y2 = q0[y2] ^ b2(L[2]);
			y3 = q0[y3] ^ b3(L[2]);
		case 2:
			y0 = q1[  q0 [ q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
			y1 = q0[  q0 [ q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
			y2 = q1[  q1 [ q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
			y3 = q0[  q1 [ q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
		}

		/* now do the partial MDS matrix multiplies */
		QF[0][i] = (
		    (multEF[y0] << 24) |
		    (multEF[y0] << 16) |
		    (mult5B[y0] <<  8) |
		    (y0              ));
		QF[1][i] = (
		    (y1         << 24) |
		    (mult5B[y1] << 16) |
		    (multEF[y1] <<  8) |
		    (multEF[y1]      ));
		QF[2][i] = (
		    (multEF[y2] << 24) |
		    (y2         << 16) |
		    (multEF[y2] <<  8) |
		    (mult5B[y2]      ));
		QF[3][i] = (
		    (mult5B[y3] << 24) |
		    (multEF[y3] << 16) |
		    (y3         <<  8) |
		    (mult5B[y3]      ));
	} while (++i); /* 256 iterations */
}

/* g() (4.2) */
static inline uint32_t
tf_g(uint32_t x, uint32_t S[4][0x100])
{
	return S[0][b0(x)] ^ S[1][b1(x)] ^ S[2][b2(x)] ^ S[3][b3(x)];
}

/* F() (4.1) */
#define tf_F(r0,r1, f0,f1, round, K, S)				do \
{								\
	uint32_t t0, t1;				\
	t0 = tf_g(r0, S);					\
	t1 = tf_g(ROL(r1, 8), S);				\
	f0 = t0 +     t1 + K[2 * round + 8];			\
	f1 = t0 + 2 * t1 + K[2 * round + 9];			\
}								while(0)

/* rotate result of F() for encryption */
#define rot_enc(f0,f1, r2,r3)					do \
{								\
	r2 = ROR(r2 ^ f0, 1);					\
	r3 = ROL(r3, 1) ^ f1;					\
}								while(0)

/* rotate result of F() for decryption */
#define rot_dec(f0,f1, r2,r3)					do \
{								\
	r2 = ROL(r2, 1) ^ f0;					\
	r3 = ROR(r3 ^ f1, 1);					\
}								while(0)

/* one encryption round */
#define ENC_ROUND(r0,r1, r2,r3, round, K, S)			do \
{								\
	uint32_t f0, f1;				\
	tf_F(r0,r1, f0,f1, round, K, S);			\
	rot_enc(f0,f1, r2,r3);					\
}								while(0)

/* one decryption round */
#define DEC_ROUND(r0,r1, r2,r3, round, K, S)			do \
{								\
	uint32_t f0, f1;				\
	tf_F(r0,r1, f0,f1, round, K, S);			\
	rot_dec(f0,f1, r2,r3);					\
}								while(0)

static inline void
encrypt(uint32_t K[40], uint32_t S[4][0x100], const uint8_t plaintext[16],
    uint8_t ciphertext[16])
{
	uint32_t	r0,r1,r2,r3;

	/* load/byteswap/whiten input */
	r0 = K[0] ^ htole32(((uint32_t *)plaintext)[0]);
	r1 = K[1] ^ htole32(((uint32_t *)plaintext)[1]);
	r2 = K[2] ^ htole32(((uint32_t *)plaintext)[2]);
	r3 = K[3] ^ htole32(((uint32_t *)plaintext)[3]);

	ENC_ROUND(r0,r1, r2,r3,  0, K, S);
	ENC_ROUND(r2,r3, r0,r1,  1, K, S);
	ENC_ROUND(r0,r1, r2,r3,  2, K, S);
	ENC_ROUND(r2,r3, r0,r1,  3, K, S);
	ENC_ROUND(r0,r1, r2,r3,  4, K, S);
	ENC_ROUND(r2,r3, r0,r1,  5, K, S);
	ENC_ROUND(r0,r1, r2,r3,  6, K, S);
	ENC_ROUND(r2,r3, r0,r1,  7, K, S);
	ENC_ROUND(r0,r1, r2,r3,  8, K, S);
	ENC_ROUND(r2,r3, r0,r1,  9, K, S);
	ENC_ROUND(r0,r1, r2,r3, 10, K, S);
	ENC_ROUND(r2,r3, r0,r1, 11, K, S);
	ENC_ROUND(r0,r1, r2,r3, 12, K, S);
	ENC_ROUND(r2,r3, r0,r1, 13, K, S);
	ENC_ROUND(r0,r1, r2,r3, 14, K, S);
	ENC_ROUND(r2,r3, r0,r1, 15, K, S);

	/* load/byteswap/whiten output */
	((uint32_t *)ciphertext)[0] = le32toh(r2 ^ K[4]);
	((uint32_t *)ciphertext)[1] = le32toh(r3 ^ K[5]);
	((uint32_t *)ciphertext)[2] = le32toh(r0 ^ K[6]);
	((uint32_t *)ciphertext)[3] = le32toh(r1 ^ K[7]);
}

static inline void
decrypt(uint32_t K[40], uint32_t S[4][256], const uint8_t ciphertext[16],
    uint8_t plaintext[16])
{
	uint32_t r0,r1,r2,r3;

	/* load/byteswap/whiten input */
	r0 = K[4] ^ htole32(((uint32_t *)ciphertext)[0]);
	r1 = K[5] ^ htole32(((uint32_t *)ciphertext)[1]);
	r2 = K[6] ^ htole32(((uint32_t *)ciphertext)[2]);
	r3 = K[7] ^ htole32(((uint32_t *)ciphertext)[3]);

	DEC_ROUND(r0,r1, r2,r3, 15, K, S);
	DEC_ROUND(r2,r3, r0,r1, 14, K, S);
	DEC_ROUND(r0,r1, r2,r3, 13, K, S);
	DEC_ROUND(r2,r3, r0,r1, 12, K, S);
	DEC_ROUND(r0,r1, r2,r3, 11, K, S);
	DEC_ROUND(r2,r3, r0,r1, 10, K, S);
	DEC_ROUND(r0,r1, r2,r3,  9, K, S);
	DEC_ROUND(r2,r3, r0,r1,  8, K, S);
	DEC_ROUND(r0,r1, r2,r3,  7, K, S);
	DEC_ROUND(r2,r3, r0,r1,  6, K, S);
	DEC_ROUND(r0,r1, r2,r3,  5, K, S);
	DEC_ROUND(r2,r3, r0,r1,  4, K, S);
	DEC_ROUND(r0,r1, r2,r3,  3, K, S);
	DEC_ROUND(r2,r3, r0,r1,  2, K, S);
	DEC_ROUND(r0,r1, r2,r3,  1, K, S);
	DEC_ROUND(r2,r3, r0,r1,  0, K, S);

	/* load/byteswap/whiten output */
	((uint32_t *)plaintext)[0] = le32toh(r2 ^ K[0]);
	((uint32_t *)plaintext)[1] = le32toh(r3 ^ K[1]);
	((uint32_t *)plaintext)[2] = le32toh(r0 ^ K[2]);
	((uint32_t *)plaintext)[3] = le32toh(r1 ^ K[3]);
}

/* the key schedule routine */
static void
key_sched(const uint8_t user_key[], uint8_t sz, uint32_t *S, uint32_t K[40])
{
	uint32_t	Me[4];
	uint32_t	Mo[4];
	uint8_t		full_key_buf[TWOFISH_KEYMAX];
	union {
		uint8_t		buf[8];
		uint32_t	words[2];
	} vector;
	const uint8_t	*key;
	/* full_sz = ceil(size/8)*8 */
	uint8_t		full_sz = (sz + 7) & ~7;
	uint8_t		word_pairs = full_sz / 8;

	if (sz != full_sz) {
		/* sz != 0 mod 8; copy to new buffer and pad with zeros
		 * until it is */
		memcpy(full_key_buf, user_key, sz);
		memset(full_key_buf + sz, 0, full_sz - sz);
		key = full_key_buf;
	} else
		key = user_key;

	for (uint8_t i = 0; i < word_pairs; i++) {
		Me[i] = htole32(((const uint32_t *)key)[2 * i    ]);
		Mo[i] = htole32(((const uint32_t *)key)[2 * i + 1]);

		/* copy b0(Me[i]) to vector.buf[0], ...; LE systems need no
		 * swap, but BE systems do */
		(vector.words)[0] = htole32(Me[i]);
		(vector.words)[1] = htole32(Mo[i]);
		S[word_pairs - i - 1] = rs_mat_mult(vector.buf);
	}

	for (uint8_t i = 0; i < 20; i++) {
		uint32_t A = tf_h(2 * i * RHO, Me, word_pairs);
		uint32_t B = ROL(tf_h(2 * i * RHO + RHO, Mo, word_pairs), 8);
		K[2 * i] = A + B;
		K[2 * i + 1] = ROL(A + 2 * B, 9);
	}
}

bool
twofish_init(struct twofish_ctx *ctx, const uint8_t *keydata, size_t sz)
{
	uint32_t	S[4];
	uint8_t		word_pairs = (sz + 7) / 8;

	if (!sz || sz > 32) return false;

	key_sched(keydata, sz, S, ctx->K);
	full_key(S, word_pairs, ctx->QF);
	return true;
}

void
twofish_encrypt(struct twofish_ctx *ctx, const uint8_t in[TWOFISH_BLOCK],
    uint8_t out[TWOFISH_BLOCK])
{
	encrypt(ctx->K, ctx->QF, in, out);
}

void
twofish_decrypt(struct twofish_ctx *ctx, const uint8_t in[TWOFISH_BLOCK],
    uint8_t out[TWOFISH_BLOCK])
{
	decrypt(ctx->K, ctx->QF, in, out);
}
