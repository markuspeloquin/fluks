/* The following code was written by Drew Csillag.  It was modified so
 * as to not memcpy functions and subsequently modify them.  That's too
 * much voodoo for my tastes. */

/*
   compiler is gcc(egcs-2.91.66)
   flags are -O3 -fomit-frame-pointer -Wall
   Processor is 233Mhz Pentium II (Deschutes)
   OS is Linux 2.2.16

   Max encryption speed I've seen (in mulit-user mode even, although single
   user mode probably won't save more than a couple clocks):

   encs/sec = 506115.904591
   bytes/sec = 8097854.473457
   KB/sec = 7908.061009
   MB/sec = 7.722716
   approx clocks/enc (for 233Mhz) = 461.027466

   I easily beat the best C implementations (the best being MSC @ 600 clocks),
   so the target is the assembly implementations...

   according to twofish docs, fully tuned *assembly* (in clocks):
   compiled is 285          (shouldn't be able to do this)  (12.5 MB/sec)
   full keyed is 315        (if I get to 460, maybe this is possible but
                             I *really* doubt it)  (11.3 MB/sec)
   partially keyed is 460   (I'm *really* close) (7.7 MB/sec)
   minimal keying is 720    (I've beat this -their C did too) (4.9 MB/sec)

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_ops.h"
#include "endian.h"
#include "twofish.h"
#include "twofish_tables.h"
#define RS_MOD 0x14D

const uint32_t RHO = 0x01010101UL;

#define TWOFISH_TESTING 0

/* get byte N of x, where 0 is the least significant byte */
#define _b(x, N) ((uint8_t)((x) >> (N)*8))

/* just casting to byte (instead of masking with 0xFF saves *tons* of clocks
   (around 50) */
#define b0(x) ((uint8_t)(x))
/* this saved 10 clocks */
#define b1(x) ((uint8_t)((x) >> 8))
/* use byte cast here saves around 10 clocks */
#define b2(x) (uint8_t)((x) >> 16)
/* don't need to mask since all bits are in lower 8 - byte cast here saves
   nothing, but hey, what the hell, it doesn't hurt any */
#define b3(x) ((x) >> 24)

/*
   multiply two polynomials represented as uint32_t's, actually called with uint8_tS,
   but since I'm not really going to too much work to optimize key setup (since
   raw encryption speed is what I'm after), big deal.
*/
static uint32_t polyMult(uint32_t a, uint32_t b)
{
    uint32_t t = 0;
    while (a)
    {
	/*printf("A=%X  B=%X  T=%X\n", a, b, t);*/
	if (a&1) t^=b;
	b <<= 1;
	a >>= 1;
    }
    return t;
}

/* take the polynomial t and return the t % modulus in GF(256) */
static uint32_t gfMod(uint32_t t, uint32_t modulus)
{
    uint32_t tt;

    modulus <<= 7;
    for (uint8_t i = 0; i < 8; i++)
    {
	tt = t ^ modulus;
	if (tt < t) t = tt;
	modulus >>= 1;
    }
    return t;
}

/*multiply a and b and return the modulus */
#define gfMult(a, b, modulus) gfMod(polyMult(a, b), modulus)

/* return a uint32_t containing the result of multiplying the RS Code matrix
   by the sd matrix
*/
static uint32_t RSMatrixMultiply(uint8_t sd[8])
{
    uint8_t result[4];

    for (uint8_t j = 0; j < 4; j++)
    {
	uint8_t t = 0;
	for (uint8_t k = 0; k < 8; k++)
	{
	    t ^= gfMult(RS[j][k], sd[k], RS_MOD);
	}
	result[3-j] = t;
    }
    return be32toh(*(uint32_t *)(result));
}

/* the Zero-keyed h function (used by the key setup routine) */
static uint32_t h(uint32_t X, uint32_t L[4], uint8_t k)
{
    uint8_t y0, y1, y2, y3;
    uint8_t z0, z1, z2, z3;
    y0 = b0(X);
    y1 = b1(X);
    y2 = b2(X);
    y3 = b3(X);

    switch(k)
    {
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
    z0 = multEF[y0] ^ y1 ^         multEF[y2] ^ mult5B[y3];
    z1 = multEF[y0] ^ mult5B[y1] ^ y2 ^         multEF[y3];
    z2 = mult5B[y0] ^ multEF[y1] ^ multEF[y2] ^ y3;
    z3 = y0 ^         multEF[y1] ^ mult5B[y2] ^ mult5B[y3];

    return z0 << 24 | z1 << 16 | z2 << 8 | z3;
}

/* given the Sbox keys, create the fully keyed QF */
static void fullKey(uint32_t L[4], uint8_t k, uint32_t QF[4][256])
{
    uint8_t y0, y1, y2, y3;

    /* for all input values to the Q permutations */
    for (uint16_t i=0; i<256; i++)
    {
	/* run the Q permutations */
	y0 = y1 = y2 = y3 = i;
	switch(k)
    	{
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
	QF[0][i] = ((multEF[y0] << 24)
		    | (multEF[y0] << 16)
		    | (mult5B[y0] << 8)
		    | y0);
	QF[1][i] = ((y1 << 24)
		    | (mult5B[y1] << 16)
		    | (multEF[y1] << 8)
		    | multEF[y1]);
	QF[2][i] = ((multEF[y2] << 24)
		    | (y2 << 16)
		    | (multEF[y2] << 8)
		    | mult5B[y2]);
	QF[3][i] = ((mult5B[y3] << 24)
		    | (multEF[y3] << 16)
		    | (y3 << 8)
		    | mult5B[y3]);
    }
}

/* fully keyed h (aka g) function */
#define fkh(X) (S[0][b0(X)]^S[1][b1(X)]^S[2][b2(X)]^S[3][b3(X)])

/* one encryption round */
#define ENC_ROUND(R0, R1, R2, R3, round)		do \
{							\
	T0 = fkh(R0);					\
	T1 = fkh(ROL(R1, 8));				\
	R2 = ROR(R2 ^ (T1 + T0 + K[2*round+8]), 1);	\
	R3 = ROL(R3, 1) ^ (2*T1 + T0 + K[2*round+9]);	\
}							while(0)

static inline void encrypt(uint32_t K[40], uint32_t S[4][256],
    const uint8_t PT[16], uint8_t CT[16])
{
    uint32_t R0, R1, R2, R3;
    uint32_t T0, T1;

    /* load/byteswap/whiten input */
    R3 = K[3] ^ htole32(((uint32_t *)PT)[3]);
    R2 = K[2] ^ htole32(((uint32_t *)PT)[2]);
    R1 = K[1] ^ htole32(((uint32_t *)PT)[1]);
    R0 = K[0] ^ htole32(((uint32_t *)PT)[0]);

    ENC_ROUND(R0, R1, R2, R3, 0);
    ENC_ROUND(R2, R3, R0, R1, 1);
    ENC_ROUND(R0, R1, R2, R3, 2);
    ENC_ROUND(R2, R3, R0, R1, 3);
    ENC_ROUND(R0, R1, R2, R3, 4);
    ENC_ROUND(R2, R3, R0, R1, 5);
    ENC_ROUND(R0, R1, R2, R3, 6);
    ENC_ROUND(R2, R3, R0, R1, 7);
    ENC_ROUND(R0, R1, R2, R3, 8);
    ENC_ROUND(R2, R3, R0, R1, 9);
    ENC_ROUND(R0, R1, R2, R3, 10);
    ENC_ROUND(R2, R3, R0, R1, 11);
    ENC_ROUND(R0, R1, R2, R3, 12);
    ENC_ROUND(R2, R3, R0, R1, 13);
    ENC_ROUND(R0, R1, R2, R3, 14);
    ENC_ROUND(R2, R3, R0, R1, 15);

    /* load/byteswap/whiten output */
    ((uint32_t *)CT)[3] = le32toh(R1 ^ K[7]);
    ((uint32_t *)CT)[2] = le32toh(R0 ^ K[6]);
    ((uint32_t *)CT)[1] = le32toh(R3 ^ K[5]);
    ((uint32_t *)CT)[0] = le32toh(R2 ^ K[4]);
}

/* one decryption round */
#define DEC_ROUND(R0, R1, R2, R3, round)		do \
{							\
	T0 = fkh(R0);					\
	T1 = fkh(ROL(R1, 8));				\
	R2 = ROL(R2, 1) ^ (T0 + T1 + K[2*round+8]);	\
	R3 = ROR(R3 ^ (T0 + 2*T1 + K[2*round+9]), 1);	\
}							while(0)

static inline void decrypt(uint32_t K[40], uint32_t S[4][256],
    const uint8_t CT[16], uint8_t PT[16])
{
    uint32_t T0, T1;
    uint32_t R0, R1, R2, R3;

    /* load/byteswap/whiten input */
    R3 = K[7] ^ htole32(((uint32_t *)CT)[3]);
    R2 = K[6] ^ htole32(((uint32_t *)CT)[2]);
    R1 = K[5] ^ htole32(((uint32_t *)CT)[1]);
    R0 = K[4] ^ htole32(((uint32_t *)CT)[0]);

    DEC_ROUND(R0, R1, R2, R3, 15);
    DEC_ROUND(R2, R3, R0, R1, 14);
    DEC_ROUND(R0, R1, R2, R3, 13);
    DEC_ROUND(R2, R3, R0, R1, 12);
    DEC_ROUND(R0, R1, R2, R3, 11);
    DEC_ROUND(R2, R3, R0, R1, 10);
    DEC_ROUND(R0, R1, R2, R3, 9);
    DEC_ROUND(R2, R3, R0, R1, 8);
    DEC_ROUND(R0, R1, R2, R3, 7);
    DEC_ROUND(R2, R3, R0, R1, 6);
    DEC_ROUND(R0, R1, R2, R3, 5);
    DEC_ROUND(R2, R3, R0, R1, 4);
    DEC_ROUND(R0, R1, R2, R3, 3);
    DEC_ROUND(R2, R3, R0, R1, 2);
    DEC_ROUND(R0, R1, R2, R3, 1);
    DEC_ROUND(R2, R3, R0, R1, 0);

    /* load/byteswap/whiten output */
    ((uint32_t *)PT)[3] = le32toh(R1 ^ K[3]);
    ((uint32_t *)PT)[2] = le32toh(R0 ^ K[2]);
    ((uint32_t *)PT)[1] = le32toh(R3 ^ K[1]);
    ((uint32_t *)PT)[0] = le32toh(R2 ^ K[0]);

}

/* the key schedule routine */
static void keySched(const uint8_t M[], uint16_t N, uint32_t **S,
    uint32_t K[40], uint8_t *k)
{
    uint32_t Me[4];
    uint32_t Mo[4];
    uint8_t vector[8];

    *k = (N + 63) / 64;
    *S = (uint32_t *)malloc(4 * *k);

    /* 2*i+1 gets as large as 127 */
    for (uint8_t i = 0; i < *k; i++)
    {
	Me[i] = htole32(((const uint32_t*)M)[2*i]);
	Mo[i] = htole32(((const uint32_t*)M)[2*i+1]);
    }

    for (uint8_t i = 0; i < *k; i++)
    {
	for (uint8_t j = 0; j < 4; j++) vector[j] = _b(Me[i], j);
	for (uint8_t j = 0; j < 4; j++) vector[j+4] = _b(Mo[i], j);
	(*S)[(*k)-i-1] = RSMatrixMultiply(vector);
    }
    for (uint8_t i = 0; i < 20; i++)
    {
	uint32_t A = h(2*i*RHO, Me, *k);
	uint32_t B = ROL(h(2*i*RHO + RHO, Mo, *k), 8);
	K[2*i] = A+B;
	K[2*i+1] = ROL(A + 2*B, 9);
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
	memcpy(k, k1, 16);
	memcpy(k+16, k2, 16);

	keySched(k, n, &KS, K, &Kk);
	fullKey(KS, Kk, QF);
	free(KS);
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
    uint32_t *S;
    int i;
    uint8_t k;

    memset(text, 0, 16);
    memset(key, 0, 32);
    keySched(key, 128, &S, K, &k);
    fullKey(S, k, QF);
    free(S);

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
    uint32_t *S;
    uint8_t k;

    /* a few tests to make sure we didn't break anything */
#if 1
    /*test encryption of null string with null key*/
    memset(text, 0, 16);
    memset(key, 0, 32);
    keySched(key, 128, &S, K, &k);
    fullKey(S, k, QF);
    fflush(stdout);

    free(S);
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
    keySched(key, 128, &S, K, &k);
    fullKey(S, k, QF);
    free(S);
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
	uint32_t *S;
	uint8_t k;

	if (sz != 16 && sz != 24 && sz != 32) return false;

	keySched(keydata, sz * 8, &S, ctx->K, &k);
	fullKey(S, k, ctx->QF);
	free(S);
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
