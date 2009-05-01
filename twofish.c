/* The following code was written by Drew Csillag.  It was modified so
 * as to not memcpy functions and subsequently modify them.  That's too
 * much voodoo for my tastes.  Also, macros are used less, malloc()/free()
 * removed from key schedule, and the code was generally cleaned up.  */

#include <string.h>

#include "crypto_ops.h"
#include "endian.h"
#include "twofish.h"
#include "twofish_tables.h"

#define TWOFISH_TESTING 0

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
 * uint8_t'S, but since I'm not really going to too much work to optimize
 * key setup (since raw encryption speed is what I'm after), big deal. */
static inline uint32_t
polyMult(uint32_t a, uint32_t b)
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
gfMod(uint32_t t, uint32_t modulus)
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
gfMult(uint32_t a, uint32_t b, uint32_t modulus)
{
	return gfMod(polyMult(a, b), modulus);
}

/* return a uint32_t containing the result of multiplying the RS Code matrix
 * by the sd matrix */
static uint32_t
RSMatrixMultiply(uint8_t sd[8])
{
	uint8_t		result[4];

	for (uint8_t j = 0; j < 4; j++) {
		uint8_t t = 0;
		for (uint8_t k = 0; k < 8; k++)
			t ^= gfMult(RS[j][k], sd[k], RS_MOD);
		result[3 - j] = t;
	}
	return be32toh(*(uint32_t *)result);
}

/* the Zero-keyed h function (used by the key setup routine) */
static uint32_t
h(uint32_t X, uint32_t L[4], uint8_t k)
{
	uint8_t		y0,y1,y2,y3;
	uint8_t		z0,z1,z2,z3;
	y0 = b0(X);
	y1 = b1(X);
	y2 = b2(X);
	y3 = b3(X);

	switch(k) {
	case 4:
		y0 = Q1[y0] ^ b0(L[3]);
		y1 = Q0[y1] ^ b1(L[3]);
		y2 = Q0[y2] ^ b2(L[3]);
		y3 = Q1[y3] ^ b3(L[3]);
	case 3:
		y0 = Q1[y0] ^ b0(L[2]);
		y1 = Q1[y1] ^ b1(L[2]);
		y2 = Q0[y2] ^ b2(L[2]);
		y3 = Q0[y3] ^ b3(L[2]);
	case 2:
		y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
		y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
		y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
		y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
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
fullKey(uint32_t L[4], uint8_t k, uint32_t QF[4][256])
{
	uint32_t	y0,y1,y2,y3;
	uint8_t		i = 0;

	/* for all input values to the Q permutations */
	do {
		/* run the Q permutations */
		y0 = y1 = y2 = y3 = i;
		switch(k) {
		case 4:
			y0 = Q1[y0] ^ b0(L[3]);
			y1 = Q0[y1] ^ b1(L[3]);
			y2 = Q0[y2] ^ b2(L[3]);
			y3 = Q1[y3] ^ b3(L[3]);
		case 3:
			y0 = Q1[y0] ^ b0(L[2]);
			y1 = Q1[y1] ^ b1(L[2]);
			y2 = Q0[y2] ^ b2(L[2]);
			y3 = Q0[y3] ^ b3(L[2]);
		case 2:
			y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
			y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
			y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
			y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
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

/* fully keyed h (aka g) function */
static inline uint32_t
fkh(uint32_t x, uint32_t S[4][256])
{
	return (S[0][b0(x)] ^ S[1][b1(x)] ^ S[2][b2(x)] ^ S[3][b3(x)]);
}

/* one encryption round */
#define ENC_ROUND(t0, t1, r0, r1, r2, r3, round, K, S)		do \
{								\
	t0 = fkh(r0, S);					\
	t1 = fkh(ROL(r1, 8), S);				\
	r2 = ROR(r2 ^ (t1 + t0 + K[2 * round + 8]), 1);		\
	r3 = ROL(r3, 1) ^ (2 * t1 + t0 + K[2 * round + 9]);	\
}								while(0)

static inline void
encrypt(uint32_t K[40], uint32_t S[4][256], const uint8_t plaintext[16],
    uint8_t ciphertext[16])
{
	register uint32_t	r0,r1,r2,r3;
	register uint32_t	t0,t1;

	/* load/byteswap/whiten input */
	r3 = K[3] ^ htole32(((uint32_t *)plaintext)[3]);
	r2 = K[2] ^ htole32(((uint32_t *)plaintext)[2]);
	r1 = K[1] ^ htole32(((uint32_t *)plaintext)[1]);
	r0 = K[0] ^ htole32(((uint32_t *)plaintext)[0]);

	ENC_ROUND(t0, t1, r0, r1, r2, r3,  0, K, S);
	ENC_ROUND(t0, t1, r2, r3, r0, r1,  1, K, S);
	ENC_ROUND(t0, t1, r0, r1, r2, r3,  2, K, S);
	ENC_ROUND(t0, t1, r2, r3, r0, r1,  3, K, S);
	ENC_ROUND(t0, t1, r0, r1, r2, r3,  4, K, S);
	ENC_ROUND(t0, t1, r2, r3, r0, r1,  5, K, S);
	ENC_ROUND(t0, t1, r0, r1, r2, r3,  6, K, S);
	ENC_ROUND(t0, t1, r2, r3, r0, r1,  7, K, S);
	ENC_ROUND(t0, t1, r0, r1, r2, r3,  8, K, S);
	ENC_ROUND(t0, t1, r2, r3, r0, r1,  9, K, S);
	ENC_ROUND(t0, t1, r0, r1, r2, r3, 10, K, S);
	ENC_ROUND(t0, t1, r2, r3, r0, r1, 11, K, S);
	ENC_ROUND(t0, t1, r0, r1, r2, r3, 12, K, S);
	ENC_ROUND(t0, t1, r2, r3, r0, r1, 13, K, S);
	ENC_ROUND(t0, t1, r0, r1, r2, r3, 14, K, S);
	ENC_ROUND(t0, t1, r2, r3, r0, r1, 15, K, S);

	/* load/byteswap/whiten output */
	((uint32_t *)ciphertext)[3] = le32toh(r1 ^ K[7]);
	((uint32_t *)ciphertext)[2] = le32toh(r0 ^ K[6]);
	((uint32_t *)ciphertext)[1] = le32toh(r3 ^ K[5]);
	((uint32_t *)ciphertext)[0] = le32toh(r2 ^ K[4]);
}

/* one decryption round */
#define DEC_ROUND(t0,t1, r0,r1,r2,r3, round, K, S)		do \
{								\
	t0 = fkh(r0, S);					\
	t1 = fkh(ROL(r1, 8), S);				\
	r2 = ROL(r2, 1) ^ (t0 + t1 + K[2 * round + 8]);		\
	r3 = ROR(r3 ^ (t0 + 2 * t1 + K[2 * round + 9]), 1);	\
}								while(0)

static inline void
decrypt(uint32_t K[40], uint32_t S[4][256], const uint8_t ciphertext[16],
    uint8_t plaintext[16])
{
	register uint32_t r0,r1,r2,r3;
	register uint32_t t0,t1;

	/* load/byteswap/whiten input */
	r3 = K[7] ^ htole32(((uint32_t *)ciphertext)[3]);
	r2 = K[6] ^ htole32(((uint32_t *)ciphertext)[2]);
	r1 = K[5] ^ htole32(((uint32_t *)ciphertext)[1]);
	r0 = K[4] ^ htole32(((uint32_t *)ciphertext)[0]);

	DEC_ROUND(t0, t1, r0, r1, r2, r3, 15, K, S);
	DEC_ROUND(t0, t1, r2, r3, r0, r1, 14, K, S);
	DEC_ROUND(t0, t1, r0, r1, r2, r3, 13, K, S);
	DEC_ROUND(t0, t1, r2, r3, r0, r1, 12, K, S);
	DEC_ROUND(t0, t1, r0, r1, r2, r3, 11, K, S);
	DEC_ROUND(t0, t1, r2, r3, r0, r1, 10, K, S);
	DEC_ROUND(t0, t1, r0, r1, r2, r3,  9, K, S);
	DEC_ROUND(t0, t1, r2, r3, r0, r1,  8, K, S);
	DEC_ROUND(t0, t1, r0, r1, r2, r3,  7, K, S);
	DEC_ROUND(t0, t1, r2, r3, r0, r1,  6, K, S);
	DEC_ROUND(t0, t1, r0, r1, r2, r3,  5, K, S);
	DEC_ROUND(t0, t1, r2, r3, r0, r1,  4, K, S);
	DEC_ROUND(t0, t1, r0, r1, r2, r3,  3, K, S);
	DEC_ROUND(t0, t1, r2, r3, r0, r1,  2, K, S);
	DEC_ROUND(t0, t1, r0, r1, r2, r3,  1, K, S);
	DEC_ROUND(t0, t1, r2, r3, r0, r1,  0, K, S);

	/* load/byteswap/whiten output */
	((uint32_t *)plaintext)[3] = le32toh(r1 ^ K[3]);
	((uint32_t *)plaintext)[2] = le32toh(r0 ^ K[2]);
	((uint32_t *)plaintext)[1] = le32toh(r3 ^ K[1]);
	((uint32_t *)plaintext)[0] = le32toh(r2 ^ K[0]);
}

/* the key schedule routine */
static void
keySched(const uint8_t M[], uint16_t N, uint32_t *S, uint32_t K[40],
    uint8_t k)
{
	uint32_t	Me[4];
	uint32_t	Mo[4];
	uint8_t		vector[8];

	/* 2*i+1 gets as large as 127 */
	for (uint8_t i = 0; i < k; i++) {
		Me[i] = htole32(((const uint32_t*)M)[2 * i]);
		Mo[i] = htole32(((const uint32_t*)M)[2 * i + 1]);
	}

	for (uint8_t i = 0; i < k; i++) {
		for (uint8_t j = 0; j < 4; j++) vector[j]     = b_n(Me[i], j);
		for (uint8_t j = 0; j < 4; j++) vector[j + 4] = b_n(Mo[i], j);
		S[k - i - 1] = RSMatrixMultiply(vector);
	}
	for (uint8_t i = 0; i < 20; i++) {
		uint32_t A = h(2 * i * RHO, Me, k);
		uint32_t B = ROL(h(2 * i * RHO + RHO, Mo, k), 8);
		K[2 * i] = A + B;
		K[2 * i + 1] = ROL(A + 2 * B, 9);
	}
}

#if TWOFISH_TESTING
/***********************************************************************
  TESTING FUNCTIONS AND STUFF STARTS HERE
***********************************************************************/
static void printHex(uint8_t b[], int lim)
{
    int i;
    for (i=0; i<lim;i++)
	printf("%02X", (uint32_t)b[i]);
}


/* the ECB tests */
static void Itest(uint16_t n)
{
    uint8_t ct[16], nct[16], k1[16], k2[16], k[32];

    uint32_t QF[4][256];
    uint32_t *KS;
    uint32_t K[40];
    int i;
    uint8_t Kk;

    memset(ct, 0, 16);
    memset(nct, 0, 16);
    memset(k1, 0, 16);
    memset(k2, 0, 16);

    for (i=0; i<49; i++)
    {
	uint32_t KS[4];
	uint8_t Kk = (n + 63) / 64;

	memcpy(k, k1, 16);
	memcpy(k+16, k2, 16);

	keySched(k, n, KS, K, Kk);
	fullKey(KS, Kk, QF);
	/*printSubkeys(K);*/
	memcpy(nct, ct, 16);
	encrypt(K, QF, nct, nct);
	/*        encrypt(K, QF, nct, nct);   FIXME--ATC*/
	printf("\nI=%d\n", i+1);
	printf("KEY=");
	printHex(k, n/8);
	printf("\n");
	printf("PT="); printHex(ct, 16); printf("\n");
	printf("CT="); printHex(nct, 16); printf("\n");
	memcpy(k2, k1, 16);
	memcpy(k1, ct, 16);
	memcpy(ct, nct, 16);
    }
}

#include <sys/time.h>
#include <unistd.h>
#include <time.h>

static double getTimeDiff(struct timeval t1, struct timeval t2)
{
    long us1;
    long us2;
    us1 = t2.tv_sec - t1.tv_sec;
    us2 = t2.tv_usec - t1.tv_usec;
    if (us2 < 0)
    {
	us1--;
	us2 += 1000000;
    }
    return us1 + (us2 / 1000000.0);
}

/* a million encryptions should give us a good feel for how we're doing */
#define NUMTIMES 1000000
static void bench()
{
    struct timeval tv_start, tv_end;
    uint32_t K[40];
    uint32_t QF[4][256];
    uint8_t text[16];
    uint8_t key[32];
    double diff;
    uint32_t S[2];
    int i;
    uint8_t k = 2;

    memset(text, 0, 16);
    memset(key, 0, 32);
    keySched(key, 128, S, K, k);
    fullKey(S, k, QF);

    gettimeofday(&tv_start, NULL);
    for (i=0; i < NUMTIMES; i++)
	encrypt(K, QF, text, text);
    gettimeofday(&tv_end, NULL);

    diff = getTimeDiff(tv_start, tv_end);
    printf("encs/sec = %f\n", NUMTIMES/diff);
    printf("bytes/sec = %f\n", (NUMTIMES*16)/diff);
    printf("KB/sec = %f\n", NUMTIMES/(diff*64));
    printf("MB/sec = %f\n", NUMTIMES/(diff*65536));
    printf("approx clocks/enc (for 233Mhz) = %f\n", 233333333/(NUMTIMES/diff));
}

int main()
{
    uint32_t K[40];
    uint32_t QF[4][256];
    uint8_t text[16];
    uint8_t key[32];
    uint32_t S[2];
    uint8_t k = 2;

    /* a few tests to make sure we didn't break anything */
#if 1
    /*test encryption of null string with null key*/
    memset(text, 0, 16);
    memset(key, 0, 32);
    keySched(key, 128, S, K, k);
    fullKey(S, k, QF);
    fflush(stdout);

    puts("before"); printHex(text, 16); printf("\n");
    encrypt(K, QF, text, text);
    puts("after"); printHex(text, 16); printf("\n");

    /*
       I=3 encryption from ECB test, again to make sure we didn't
       break anything
    */
    memcpy(key,  "\x9F\x58\x9F\x5C\xF6\x12\x2C\x32"
	         "\xB6\xBF\xEC\x2F\x2A\xE8\xC3\x5A", 16);
    memcpy(text, "\xD4\x91\xDB\x16\xE7\xB1\xC3\x9E"
	         "\x86\xCB\x08\x6B\x78\x9F\x54\x19", 16);
    keySched(key, 128, S, K, k);
    fullKey(S, k, QF);
    printf("before-->"); printHex(text, 16); printf("\n");
    encrypt(K, QF, text, text);
    printf("after--->"); printHex(text, 16); printf("\n");
    decrypt(K, QF, text, text);
    printf("after--->"); printHex(text, 16); printf("\n");
#endif
    /*Itest(128);*/

    bench();
    return 0;
}
#endif /* TF_TESTING */


bool
twofish_init(struct twofish_ctx *ctx, const uint8_t *keydata, size_t sz)
{
	uint32_t	S[4];
	uint8_t		k = sz / 8;

	if (sz != 16 && sz != 24 && sz != 32) return false;

	keySched(keydata, sz * 8, S, ctx->K, k);
	fullKey(S, k, ctx->QF);
	return true;
}

void
twofish_encrypt(struct twofish_ctx *ctx, const uint8_t *in, uint8_t *out)
{
	encrypt(ctx->K, ctx->QF, in, out);
}

void
twofish_decrypt(struct twofish_ctx *ctx, const uint8_t *in, uint8_t *out)
{
	decrypt(ctx->K, ctx->QF, in, out);
}
