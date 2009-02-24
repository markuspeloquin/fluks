/***************************************************************************
twofish.c	-- C API calls for TWOFISH AES submission

Submitters:
	Bruce Schneier, Counterpane Systems
	Doug Whiting,	Hi/fn
	John Kelsey,	Counterpane Systems
	Chris Hall,	Counterpane Systems
	David Wagner,	UC Berkeley

Code Author:
	Doug Whiting,	Hi/fn

Version 1.0		April 1998

Copyright 1998, Hi/fn and Counterpane Systems.  All rights reserved.

Notes:
	Pedagogical version (non-optimized)

***************************************************************************/

/* Markus (markus@cs.wisc.edu):
 * I stripped all the debug code, reformatted for 80 columns and 8-column
 * tab stops, and generally removed wackyness. */

#include <assert.h>
#include <ctype.h>
#include <string.h>

#include "twofish.h"
#include "twofish_debug.h"
#include "twofish_platform.h"
#include "twofish_table.h"

#ifdef DEBUG
#	define CHECK_ALIGN
#	define CHECK_ARGS

#	define IV_ROUND	-100

extern bool	debug;
void		debug_io(const char *s);
#endif

bool		tabEnable = false;	/* are we gathering stats? */
uint8_t		tabUsed[256];		/* one bit per table */

const char	*moduleDescription = "Pedagogical C code";
const char	*modeString = "";

#define	P0_USED		0x01
#define	P1_USED		0x02
#define	B0_USED		0x04
#define	B1_USED		0x08
#define	B2_USED		0x10
#define	B3_USED		0x20
#define	ALL_USED	0x3F

/* default number of rounds for 128/192/256-bit keys */
#define	ROUNDS_128	16
#define	ROUNDS_192	16
#define	ROUNDS_256	16

/* initialization signature ('FISH') */
#define VALID_SIG	 0x48534946

/* number of rounds for various key sizes: 128, 192, 256 */
uint8_t		numRounds[4] = { 0, ROUNDS_128, ROUNDS_192, ROUNDS_256 };


/** Use (12,8) Reed-Solomon code over GF(256) to produce a key S-box word from
 * two key material words
 *
 * Since this computation is done only once per re_key per 64 bits of key,
 * the performance impact of this routine is imperceptible. The RS code
 * chosen has "simple" coefficients to allow smartcard/hardware implementation
 * without lookup tables.
 *
 * \param k0	First word.
 * \param k1	Second word.
 * \return	Remainder polynomial generated using RS code.
 */
static uint32_t	RS_MDS_Encode(uint32_t k0, uint32_t k1);

/** Run four bytes through keyede S-boxes and apply MDS matrix
 *
 * This function is a keyed 32-bit permutation.  It is the major building
 * block for the Twofish round function, including the four keyed 8x8
 * permutations and the 4x4 MDS matrix multiply.  This function is used
 * both for generating round subkeys and within the round function on the
 * block being encrypted.
 *
 * This version is fairly slow and pedagogical, although a smartcard would
 * probably perform the operation exactly this way in firmware.   For
 * ultimate performance, the entire operation can be completed with four
 * lookups into four 256x32-bit tables, with three dword xors.
 *
 * The MDS matrix is defined in TABLE.H.  To multiply by Mij, just use the
 * macro Mij(x).
 *
 * \param x		Input to f function
 * \param k32		Pointer to key words
 * \param sz_key	total key length (k32 --> keyLen/2 bits)
 * \return		The output of the keyed permutation applied to x.
 */
static uint32_t	f32(uint32_t x, const uint32_t *k32, int sz_key);

/** Parse ASCII hex nibbles and fill in key/IV 32bit words
 *
 * Note that the parameter d is a uint32_t array, not a byte array.
 * This routine is coded to work both for little-endian and big-endian
 * architectures.  The character stream is interpreted as a LITTLE-ENDIAN
 * byte stream, since that is how the Pentium works, but the conversion
 * happens automatically below.
 *
 * \param sz		Number of bits to read
 * \param srcTxt	ASCII source
 * \param d		Pointer to words to fill in
 * \param dstText	Where to make a copy of ASCII source
 * \return		0 if no error, nonzero if invalid hex or length
 */
static int	parse_hex_le32(size_t sz, const char *srcTxt, uint32_t *d,
		    char *dstTxt);

/** Initialize the Twofish key schedule from key32
 *
 * Here we precompute all the round subkeys, although that is not actually
 * required.  For example, on a smartcard, the round subkeys can 
 * be generated on-the-fly using f32().
 *
 * \param key	Pointer to struct twofish_key to be initialized
 * \return	True iff success.
 */
static bool	re_key(struct twofish_key *key);


bool
do_table_op(enum table_op op)
{
	static int queryCnt = 0;
	switch (op) {
	case TAB_DISABLE:
		tabEnable = false;
		break;
	case TAB_ENABLE:
		tabEnable = true;
		break;
	case TAB_RESET:
		queryCnt = 0;
		for (uint16_t i = 0; i < 256; i++)
			tabUsed[i] = 0;
		break;
	case TAB_QUERY:
		queryCnt++;
		for (uint16_t i = 0; i < 256; i++)
			if (tabUsed[i] != ALL_USED)
				return false;
		/* do a certain minimum number */
		if (queryCnt < TAB_MIN_QUERY)
			return false;
		break;
	default:
		break;
	}
	return true;
}

static int
parse_hex_le32(size_t sz, const char *srcTxt, uint32_t *d, char *dstTxt)
{
	/* number of bits to left-shift by for hex digit i mod 8 */
	const uint8_t SHIFTS[] = { 4, 0, 12, 8, 20, 16, 28, 24 };

#ifdef CHECK_ALIGN
	if ((int)d & 3)
		return BAD_ALIGN;
#endif

	/* first, zero the field */
	memset(d, 0, sz / 4);

	/* parse one nibble at a time */
	for (size_t i = 0; i < sz * 2; i++) {
		uint32_t b;
		char c;

		c = srcTxt[i];
		if (dstTxt) dstTxt[i] = c;
		if (isdigit(c))
			b = c - '0';
		else if (c >= 'a' && c <= 'f')
			b = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			b = c - 'A' + 10;
		else
			return BAD_KEY_MAT;

		d[i / 8] |= b << SHIFTS[i & 7];
	}

	return 0;
}

static uint32_t
f32(uint32_t x, const uint32_t *k32, int sz_key)
{
	uint8_t b[4];

	/* Run each byte thru 8x8 S-boxes, xoring with key byte at each
	 * stage.  Note that each byte goes through a different combination
	 * of S-boxes.*/

	/* make little-endian */
	*((uint32_t *)b) = Bswap(x);
	switch (((sz_key + 7) / 8) & 3) {
	case 0:
		/* 256 bits of key */
		b[0] = p8(04)[b[0]] ^ b0(k32[3]);
		b[1] = p8(14)[b[1]] ^ b1(k32[3]);
		b[2] = p8(24)[b[2]] ^ b2(k32[3]);
		b[3] = p8(34)[b[3]] ^ b3(k32[3]);
		/* fall thru, having pre-processed b[0]..b[3] with k32[3] */
	case 3:
		/* 192 bits of key */
		b[0] = p8(03)[b[0]] ^ b0(k32[2]);
		b[1] = p8(13)[b[1]] ^ b1(k32[2]);
		b[2] = p8(23)[b[2]] ^ b2(k32[2]);
		b[3] = p8(33)[b[3]] ^ b3(k32[2]);
		/* fall thru, having pre-processed b[0]..b[3] with k32[2] */
	case 2:
		/* 128 bits of key */
		b[0] = p8(00)[p8(01)[p8(02)[b[0]] ^ b0(k32[1])] ^ b0(k32[0])];
		b[1] = p8(10)[p8(11)[p8(12)[b[1]] ^ b1(k32[1])] ^ b1(k32[0])];
		b[2] = p8(20)[p8(21)[p8(22)[b[2]] ^ b2(k32[1])] ^ b2(k32[0])];
		b[3] = p8(30)[p8(31)[p8(32)[b[3]] ^ b3(k32[1])] ^ b3(k32[0])];
	}

	if (tabEnable) {
		/* we could give a "tighter" bound, but this works
		 * acceptably well */
		tabUsed[b0(x)] |= P_00 ? P1_USED : P0_USED;
		tabUsed[b1(x)] |= P_10 ? P1_USED : P0_USED;
		tabUsed[b2(x)] |= P_20 ? P1_USED : P0_USED;
		tabUsed[b3(x)] |= P_30 ? P1_USED : P0_USED;

		tabUsed[b[0] ] |= B0_USED;
		tabUsed[b[1] ] |= B1_USED;
		tabUsed[b[2] ] |= B2_USED;
		tabUsed[b[3] ] |= B3_USED;
	}

	/* Now perform the MDS matrix multiply inline. */
	return
	    (M00(b[0]) ^ M01(b[1]) ^ M02(b[2]) ^ M03(b[3]))       ^
	    (M10(b[0]) ^ M11(b[1]) ^ M12(b[2]) ^ M13(b[3])) <<  8 ^
	    (M20(b[0]) ^ M21(b[1]) ^ M22(b[2]) ^ M23(b[3])) << 16 ^
	    (M30(b[0]) ^ M31(b[1]) ^ M32(b[2]) ^ M33(b[3])) << 24 ;
}

static uint32_t
RS_MDS_Encode(uint32_t k0, uint32_t k1)
{
	uint32_t r;
	uint8_t i, j;

	for (i = r = 0; i < 2; i++) {
		/* merge in 32 more key bits */
		r ^= i ? k0 : k1;

		/* shift one byte at a time */
		for (j = 0; j < 4; j++)
			RS_rem(r);
	}
	return r;
}

static bool
re_key(struct twofish_key *key)
{
	/* even/odd key words */
	uint32_t	k32e[MAX_SZ_KEY / 8];
	uint32_t	k32o[MAX_SZ_KEY / 8];
	uint32_t	A;
	uint32_t	B;
	size_t		k64Cnt;
	size_t		sz_key = key->sz_key;
	unsigned	subkeyCnt = ROUND_SUBKEYS + 2 * key->numRounds;

#ifdef CHECK_ARGS
	/* check size is multiple of 8 */
	if (key->sz_key & 0x7 || sz_key < MIN_SZ_KEY ||
	    subkeyCnt > TOTAL_SUBKEYS)
		return BAD_KEY_INSTANCE;
#endif
#ifdef CHECK_ALIGN
	if ((int)key & 3 || (int)key->key32 & 3)
		return BAD_ALIGN;
#endif

	/* ceil(sz_key/8) */
	k64Cnt = (sz_key + 7) / 8;
	for (size_t i = 0; i < k64Cnt; i++) {
		/* split into even/odd key dwords */
		k32e[i] = key->key32[2 * i];
		k32o[i] = key->key32[2 * i + 1];

		/* compute S-box keys using (12,8) Reed-Solomon code over
		 * GF(256) */

		/* reverse order */
		key->sboxKeys[k64Cnt - 1 - i] =
		    RS_MDS_Encode(k32e[i], k32o[i]);
	}

	for (unsigned i = 0; i < subkeyCnt / 2; i++) {
		/* compute round subkeys for PHT */
		/* A uses even key words, B odd */
		A = f32(i * SK_STEP, k32e, sz_key);
		B = f32(i * SK_STEP + SK_BUMP, k32o, sz_key);
		B = ROL(B, 8);
		/* combine with a PHT */
		key->subKeys[2 * i] = A + B;
		key->subKeys[2 * i + 1] = ROL(A + 2 * B, SK_ROTL);
	}

#ifdef DEBUG
	twofish_debug_dump_key(key);
#endif

	return true;
}

int
make_key(struct twofish_key *key, int sz_key, const char *keyMaterial)
{
#ifdef CHECK_ARGS
	if (!key)	return BAD_PARAMS;
	if (sz_key > MAX_SZ_KEY || sz_key < 1)
		return BAD_KEY_MAT;
	key->keySig = VALID_SIG;
#endif
#ifdef CHECK_ALIGN
	if ((int)key & 3 || (int)key->key32 & 3)
		return BAD_ALIGN;
#endif

	key->sz_key = (sz_key + 7) / 8;
	key->numRounds = numRounds[(sz_key * 8 - 1) / 64];

	/* zero unused bits */
	for (size_t i = 0; i < MAX_SZ_KEY / 4; i++)
		key->key32[i] = 0;
	key->keyMaterial[MAX_SZ_AKEY] = '\0';

	if (!keyMaterial || !*keyMaterial)
		/* allow a 'dummy' call */
		return 1;

	if (parse_hex_le32(sz_key, keyMaterial, key->key32, key->keyMaterial))
		return BAD_KEY_MAT;

	/* generate round subkeys */
	return re_key(key);
}

int
cipherInit(struct twofish_cipher *cipher, uint8_t mode, const char *IV)
{
#ifdef CHECK_ARGS
	if (!cipher) return BAD_PARAMS;
	if (mode != MODE_ECB && mode != MODE_CBC && mode != MODE_CFB1)
		return BAD_CIPHER_MODE;
	cipher->cipherSig = VALID_SIG;
#endif
#ifdef CHECK_ALIGN
	if ((int)cipher & 3 || (int)cipher->IV & 3 || (int)cipher->iv32 & 3)
		return BAD_ALIGN;
#endif

	if (mode != MODE_ECB && IV) {
		/* parse the IV */
		if (parse_hex_le32(BLOCK_SIZE, IV, cipher->iv32, 0))
			return BAD_IV_MAT;

		/* make byte-oriented copy for CFB1 */
		for (size_t i = 0; i < BLOCK_SIZE / 4; i++)
			((uint32_t *)cipher->IV)[i] = Bswap(cipher->iv32[i]);
	}

	cipher->mode = mode;

	return 1;
}

ssize_t
twofish_encrypt(struct twofish_cipher *cipher, struct twofish_key *key,
    const uint8_t *input, size_t sz_in, uint8_t *outBuffer)
{
	/* block being encrypted */
	uint32_t	x[BLOCK_SIZE / 4];
	size_t		num_bits = sz_in * 8;
	unsigned	rounds = key->numRounds;

#ifdef CHECK_ARGS
	if (!cipher || cipher->cipherSig != VALID_SIG)
		return BAD_CIPHER_STATE;
	if (!key || key->keySig != VALID_SIG ||
	    rounds < 2 || rounds > MAX_ROUNDS || rounds & 1)
		return BAD_KEY_INSTANCE;
	if (cipher->mode != MODE_CFB1 && sz_in & (BLOCK_SIZE - 1))
		return BAD_INPUT_LEN;
#endif
#ifdef CHECK_ALIGN
	if ((int)cipher & 3 || (int)key & 3 ||
	    (int)input & 3 || (int)outBuffer & 3)
		return BAD_ALIGN;
#endif

	if (cipher->mode == MODE_CFB1) {
		/* use recursion here to handle CFB, one block at a time;
		 * do encryption in ECB */
		cipher->mode = MODE_ECB;
		for (size_t n = 0; n < num_bits; n++) {
			uint8_t bit;
			uint8_t carry;
			uint8_t ctBit;

			twofish_encrypt(cipher, key, cipher->IV, BLOCK_SIZE,
			    (uint8_t *)x);

			/* which bit pos in byte */
			bit = 0x80 >> (n & 7);
			ctBit = (input[n / 8] & bit) ^
			    (*(uint8_t *)x & 0x80) >> (n & 7);
			outBuffer[n / 8] = (outBuffer[n / 8] & ~bit) | ctBit;
			carry = ctBit >> (7 - (n & 7));
			for (unsigned i = BLOCK_SIZE - 1;; i--) {
				/* save next 'carry' from shift */
				bit = cipher->IV[i] >> 7;
				cipher->IV[i] = (cipher->IV[i] << 1) ^ carry;
				carry = bit;

				if (!i) break;
			}
		}
		/* restore mode for next time */
		cipher->mode = MODE_CFB1;
		assert(!(num_bits & 7));
		return num_bits / 8;
	}

	/* here for ECB, CBC modes */
	for (size_t n = 0; n < num_bits;
	    n += BLOCK_SIZE * 8,
	    input += BLOCK_SIZE,
	    outBuffer += BLOCK_SIZE) {

#ifdef DEBUG
		twofish_debug_dump(input, "\n", -1, 0,
		    false, false, true, 0, 0);
		if (cipher->mode == MODE_CBC)
			twofish_debug_dump(cipher->iv32, "", IV_ROUND, 0,
			    false, false, false, 0, 0);
#endif

		/* copy in the block, add whitening */
		for (unsigned i = 0; i < BLOCK_SIZE / 4; i++) {
			x[i] = Bswap(((uint32_t *)input)[i]) ^
			    key->subKeys[INPUT_WHITEN + i];
			if (cipher->mode == MODE_CBC)
				x[i] ^= cipher->iv32[i];
		}

#ifdef DEBUG
		twofish_debug_dump(x, "", 0, 0,
		    false, false, false, 0, 0);
#endif

		/* main Twofish encryption loop */
		for (unsigned rnd = 0; rnd < rounds; rnd++) {
			uint32_t t0 = f32(    x[0]    ,
			    key->sboxKeys, key->sz_key);
			uint32_t t1 = f32(ROL(x[1], 8),
			    key->sboxKeys, key->sz_key);

			x[3]  = ROL(x[3], 1);
			/* PHT, round keys */
			x[2] ^= t0 + t1 +
			    key->subKeys[ROUND_SUBKEYS + 2 * rnd ];
			x[3] ^= t0 + 2 * t1 +
			    key->subKeys[ROUND_SUBKEYS + 2 * rnd + 1];
			x[2]  = ROR(x[2],1);

#ifdef DEBUG
			twofish_debug_dump(x, "", rnd + 1, 2 * (rnd & 1),
			    true, true, false, t0, t1);
#endif

			/* make format compatible with optimized code */
			if (rnd < rounds-1) {
				/* swap for next round */
				t0 = x[0];
				x[0] = x[2];
				x[2] = t0;

				t0 = x[1];
				x[1] = x[3];
				x[3] = t0;
			}
		}
		for (unsigned i = 0; i < BLOCK_SIZE / 4; i++) {
			/* copy out, with whitening */
			((uint32_t *)outBuffer)[i] = Bswap(
			    x[i] ^ key->subKeys[OUTPUT_WHITEN + i]);
			if (cipher->mode == MODE_CBC)
				cipher->iv32[i] = Bswap(
				    ((uint32_t *)outBuffer)[i]);
		}
	}

#ifdef DEBUG
	twofish_debug_dump(outBuffer, "", rounds + 1, 0,
	    false, false, true, 0, 0);
	if (cipher->mode == MODE_CBC)
		twofish_debug_dump(cipher->iv32, "", IV_ROUND, 0,
		    false, false, false, 0, 0);
#endif

	assert(!(num_bits & 7));
	return num_bits / 8;
}

ssize_t
twofish_decrypt(struct twofish_cipher *cipher, struct twofish_key *key,
    const uint8_t *input, size_t sz_in, uint8_t *outBuffer)
{
	uint32_t	x[BLOCK_SIZE / 4];	/* block being decrypted */
	size_t		num_bits = sz_in;
	unsigned	rounds = key->numRounds;

#ifdef CHECK_ARGS
	if (!cipher || cipher->cipherSig != VALID_SIG)
		return BAD_CIPHER_STATE;
	if (!key || key->keySig != VALID_SIG ||
	    rounds < 2 || rounds > MAX_ROUNDS || rounds & 1)
		return BAD_KEY_INSTANCE;
	if (cipher->mode != MODE_CFB1 && sz_in & (BLOCK_SIZE - 1))
		return BAD_INPUT_LEN;
#endif
#ifdef CHECK_ALIGN
	if ((int)cipher & 3 || (int)key & 3 ||
	    (int)input & 3 || (int)outBuffer & 3)
		return BAD_ALIGN;
#endif

	if (cipher->mode == MODE_CFB1) {
		/* use twofish_encrypt here to handle CFB, one block at
		 * a time */

		/* do encryption in ECB */
		cipher->mode = MODE_ECB;
		for (size_t n = 0; n < num_bits; n++) {
			uint8_t bit;
			uint8_t carry;
			uint8_t ctBit;

			twofish_encrypt(cipher, key, cipher->IV, BLOCK_SIZE,
			    (uint8_t *)x);
			bit = 0x80 >> (n & 7);
			ctBit = input[n / 8] & bit;
			outBuffer[n / 8] = (outBuffer[n / 8] & ~bit) |
			    (ctBit ^ (*(uint8_t *)x & 0x80) >> (n & 7));
			/* only one bit in ctBit */
			carry = !!ctBit;
			for (unsigned i = BLOCK_SIZE - 1;; i--) {
				/* save next 'carry' bit from shift */
				bit = cipher->IV[i] >> 7;
				cipher->IV[i] = cipher->IV[i] << 1 | carry;
				carry = bit;

				if (!i) break;
			}
		}
		/* restore mode for next time */
		cipher->mode = MODE_CFB1;
		assert(!(num_bits & 7));
		return num_bits / 8;
	}

	/* here for ECB, CBC modes */
	for (size_t n = 0; n < num_bits;
	    n += BLOCK_SIZE * 8,
	    input += BLOCK_SIZE,
	    outBuffer += BLOCK_SIZE) {

#ifdef DEBUG
		twofish_debug_dump(input, "\n", rounds + 1, 0,
		    false, false, true, 0, 0);
#endif

		/* copy in the block, add whitening */
		for (unsigned i = 0; i < BLOCK_SIZE / 4; i++)
			x[i] = Bswap(((uint32_t *)input)[i]) ^
			    key->subKeys[OUTPUT_WHITEN + i];

		/* main Twofish decryption loop */
		for (unsigned rnd = rounds - 1;; rnd--) {
			uint32_t t0 = f32(    x[0]    ,
			    key->sboxKeys, key->sz_key);
			uint32_t t1 = f32(ROL(x[1], 8),
			    key->sboxKeys, key->sz_key);

#ifdef DEBUG
			twofish_debug_dump(x, "", rnd + 1, 2 * (rnd & 1),
			    false, true, false, t0, t1);
#endif

			x[2]  = ROL(x[2], 1);
			/* PHT, round keys */
			x[2] ^= t0 + t1 +
			    key->subKeys[ROUND_SUBKEYS + 2 * rnd ];
			x[3] ^= t0 + 2 * t1 +
			    key->subKeys[ROUND_SUBKEYS + 2 * rnd + 1 ];
			x[3]  = ROR(x[3], 1);

			if (rnd) {
				/* unswap, except for last round */
				t0 = x[0];
				x[0]= x[2];
				x[2] = t0;

				t1 = x[1];
				x[1]= x[3];
				x[3] = t1;
			} else break;
		}

#ifdef DEBUG
		twofish_debug_dump(x, "", 0, 0,
		    false, false, false, 0, 0);
#endif

		for (unsigned i = 0; i < BLOCK_SIZE / 4; i++) {
			/* copy out, with whitening */
			x[i] ^= key->subKeys[INPUT_WHITEN + i];
			if (cipher->mode == MODE_CBC) {
				x[i] ^= cipher->iv32[i];
				cipher->iv32[i] = Bswap(
				    ((uint32_t *)input)[i]);
			}
			((uint32_t *)outBuffer)[i] = Bswap(x[i]);
		}

#ifdef DEBUG
		twofish_debug_dump(outBuffer, "", -1, 0,
		    false, false, true, 0, 0);
#endif
	}

	assert(!(num_bits & 7));
	return num_bits / 8;
}
