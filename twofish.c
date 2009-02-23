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

#include "twofish.h"
#include "twofish_platform.h"
#include "twofish_table.h"

/* Constants/Macros/Tables */

#define VALIDATE_PARMS	1	/* nonzero --> check all parameters */

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

/* number of rounds for various key sizes: 128, 192, 256 */
int		numRounds[4] = { 0, ROUNDS_128, ROUNDS_192, ROUNDS_256 };

/** Handle table use checking
 *
 * This routine is for use in generating the tables KAT file.
 *
 * \param op	What to do (see TAB_* defines in aes.h)
 * \return	True iff done (for TAB_QUERY)
 */
bool
TableOp(enum table_op op)
{
	static int queryCnt = 0;
	int i;
	switch (op) {
	case TAB_DISABLE:
		tabEnable = false;
		break;
	case TAB_ENABLE:
		tabEnable = true;
		break;
	case TAB_RESET:
		queryCnt = 0;
		for (i = 0; i < 256; i++)
			tabUsed[i] = 0;
		break;
	case TAB_QUERY:
		queryCnt++;
		for (i = 0; i < 256; i++)
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


/** Parse ASCII hex nibbles and fill in key/IV 32bit words
 *
 * Note that the parameter d is a uint32_t array, not a byte array.
 * This routine is coded to work both for little-endian and big-endian
 * architectures.  The character stream is interpreted as a LITTLE-ENDIAN
 * byte stream, since that is how the Pentium works, but the conversion
 * happens automatically below. 
 *
 * \param bits		Number of bits to read
 * \param srcTxt	ASCII source
 * \param d		Pointer to words to fill in
 * \param dstText	Where to make a copy of ASCII source
 * \return		0 if no error, nonzero if invalid hex or length
 */
int
ParseHexDword(int bits, const char *srcTxt, uint32_t *d, char *dstTxt)
{
	/* number of bits to left-shift by for hex digit i mod 8 */
	const uint8_t SHIFTS[] = { 4, 0, 12, 8, 20, 16, 28, 24 };

	uint32_t b;
	int i;
	char c;

	for (i = 0; i * 32 < bits; i++)
		/* first, zero the field */
		d[i] = 0;

	/* parse one nibble at a time */
	for (i = 0; i * 4 < bits; i++) {
		/* case out the hexadecimal characters */
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
 * \param keyLen	total key length (k32 --> leyLen/2 bits)
 * \return		The output of the keyed permutation applied to x.
 */
uint32_t f32(uint32_t x, const uint32_t *k32, int keyLen)
{
	uint8_t b[4];
	
	/* Run each byte thru 8x8 S-boxes, xoring with key byte at each
	 * stage.  Note that each byte goes through a different combination
	 * of S-boxes.*/

	/* make little-endian */
	*((uint32_t *)b) = Bswap(x);
	switch (((keyLen + 63) / 64) & 3) {
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

/** Use (12,8) Reed-Solomon code over GF(256) to produce a key S-box word from
 * two key material words
 *
 * Since this computation is done only once per reKey per 64 bits of key,
 * the performance impact of this routine is imperceptible. The RS code
 * chosen has "simple" coefficients to allow smartcard/hardware implementation
 * without lookup tables.
 *
 * \param k0	First word.
 * \param k1	Second word.
 * \return	Remainder polynomial generated using RS code.
 */
uint32_t RS_MDS_Encode(uint32_t k0, uint32_t k1)
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

/** Initialize the Twofish key schedule from key32
 *
 * Here we precompute all the round subkeys, although that is not actually
 * required.  For example, on a smartcard, the round subkeys can 
 * be generated on-the-fly using f32().
 *
 * \param key	Pointer to keyInstance to be initialized
 * \return	True iff success.
 */
bool reKey(keyInstance *key)
{
	/* even/odd key words */
	uint32_t	k32e[MAX_KEY_BITS / 64];
	uint32_t	k32o[MAX_KEY_BITS / 64];
	uint32_t	A;
	uint32_t	B;
	int		i;
	int		k64Cnt;
	int		keyLen = key->keyLen;
	int		subkeyCnt = ROUND_SUBKEYS + 2 * key->numRounds;

	/* ceil(keyLen/64) */
	k64Cnt = (keyLen + 63) / 64;
	for (i = 0; i < k64Cnt; i++) {
		/* split into even/odd key dwords */
		k32e[i] = key->key32[2 * i];
		k32o[i] = key->key32[2 * i + 1];

		/* compute S-box keys using (12,8) Reed-Solomon code over
		 * GF(256) */

		/* reverse order */
		key->sboxKeys[k64Cnt - 1 - i] =
		    RS_MDS_Encode(k32e[i], k32o[i]);
	}

	for (i = 0; i < subkeyCnt / 2; i++) {
		/* compute round subkeys for PHT */ 
		/* A uses even key words, B odd */
		A = f32(i * SK_STEP, k32e, keyLen);
		B = f32(i * SK_STEP + SK_BUMP, k32o, keyLen);
		B = ROL(B, 8);
		/* combine with a PHT */
		key->subKeys[2 * i] = A + B;
		key->subKeys[2 * i + 1] = ROL(A + 2 * B, SK_ROTL);
	}

	return true;
}

/** Initialize the Twofish key schedule
 *
 * This parses the key bits from keyMaterial.  No crypto stuff happens here.
 * The function reKey() is called to actually build the key schedule after
 * the keyMaterial has been parsed.
 *
 * \param key		Pointer to keyInstance to be initialized
 * \param direction	DIR_ENCRYPT or DIR_DECRYPT
 * \param keyLen	Number of bits of key text at *keyMaterial.
 * \param keyMaterial	Pointer to hex ASCII chars representing key bits.
 * \return		1 iff success, else error code
 */
int makeKey(keyInstance *key, uint8_t direction, int keyLen,
    const char *keyMaterial)
{
	int i;

	key->direction = direction;
	key->keyLen = (keyLen + 63) / 64;
	key->numRounds = numRounds[(keyLen - 1) / 64];

	/* zero unused bits */
	for (i = 0; i < MAX_KEY_BITS / 32; i++)
		key->key32[i] = 0;
	key->keyMaterial[MAX_KEY_SIZE] = '\0';

	if (!keyMaterial || *keyMaterial == '\0')
		/* allow a 'dummy' call */
		return 1;
		
	if (ParseHexDword(keyLen, keyMaterial, key->key32, key->keyMaterial))
		return BAD_KEY_MAT;	

	/* generate round subkeys */
	return reKey(key);
}


/** Initialize the Twofish cipher in a given mode
 *
 * \param cipher	Pointer to cipherINstance to be initialized
 * \param mode		MODE_ECB or MODE_CBC or MODE_CFB1
 * \param IV		pointer to hex ASCII text representing IV bytes
 * \return		1 on success, else error code
 */
int cipherInit(cipherInstance *cipher, uint8_t mode, const char *IV)
{
	int i;

	if (mode != MODE_ECB && IV) {
		/* parse the IV */
		if (ParseHexDword(BLOCK_SIZE, IV, cipher->iv32, 0))
			return BAD_IV_MAT;

		/* make byte-oriented copy for CFB1 */
		for (i = 0; i < BLOCK_SIZE / 32; i++)
			((uint32_t *)cipher->IV)[i] = Bswap(cipher->iv32[i]);
	}

	cipher->mode = mode;

	return 1;
}

/** Pointer to already initialized cipherInstance
 *
 * The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
 * If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
 * an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block 
 * sizes can be supported.
 *
 * \param cipher	Pointer to already initilaized cipherInstance
 * \param key		Pointer to already initialized keyInstance
 * \param input		Pointer to data blocks to be encrypted
 * \param inputLen	Number of bits to encrypt (multiple of blockSize)
 * \param outBuffer	Pointer to where to put encrypted blocks
 * \return		Number of bits ciphered (>=0), else error code
 */
int blockEncrypt(cipherInstance *cipher, keyInstance *key,
    const uint8_t *input, int inputLen, uint8_t *outBuffer)
{
	/* block being encrypted */
	uint32_t	x[BLOCK_SIZE / 32];
	uint32_t	t0, t1, tmp;		/* temps */
	int		i, n, r;		/* loop vars */
	int		rounds = key->numRounds;
	uint8_t		bit, ctBit, carry;	/* temps for CFB */

	if (cipher->mode == MODE_CFB1) {
		/* use recursion here to handle CFB, one block at a time;
		 * do encryption in ECB */
		cipher->mode = MODE_ECB;
		for (n = 0; n < inputLen; n++) {
			blockEncrypt(cipher, key, cipher->IV, BLOCK_SIZE,
			    (uint8_t *)x);
			/* which bit pos in byte */
			bit = 0x80 >> (n & 7);
			ctBit = (input[n / 8] & bit) ^
			    (*(uint8_t *)x & 0x80) >> (n & 7);
			outBuffer[n / 8] = (outBuffer[n / 8] & ~bit) | ctBit;
			carry = ctBit >> (7 - (n & 7));
			for (i = BLOCK_SIZE / 8 - 1; i >= 0; i--) {
				/* save next 'carry' from shift */
				bit = cipher->IV[i] >> 7;
				cipher->IV[i] = (cipher->IV[i] << 1) ^ carry;
				carry = bit;
			}
		}
		/* restore mode for next time */
		cipher->mode = MODE_CFB1;
		return inputLen;
	}

	/* here for ECB, CBC modes */
	for (n = 0; n < inputLen;
	    n += BLOCK_SIZE,
	    input += BLOCK_SIZE / 8,
	    outBuffer += BLOCK_SIZE / 8) {
		/* copy in the block, add whitening */
		for (i = 0; i < BLOCK_SIZE / 32; i++) {
			x[i] = Bswap(((uint32_t *)input)[i]) ^
			    key->subKeys[INPUT_WHITEN + i];
			if (cipher->mode == MODE_CBC)
				x[i] ^= cipher->iv32[i];
		}

		for (r = 0; r < rounds; r++) {
			/* main Twofish encryption loop */
			t0 = f32(    x[0]    , key->sboxKeys, key->keyLen);
			t1 = f32(ROL(x[1], 8), key->sboxKeys, key->keyLen);

			x[3]  = ROL(x[3], 1);
			/* PHT, round keys */
			x[2] ^= t0 + t1 +
			    key->subKeys[ROUND_SUBKEYS + 2 * r  ];
			x[3] ^= t0 + 2 * t1 +
			    key->subKeys[ROUND_SUBKEYS + 2 * r + 1];
			x[2]  = ROR(x[2],1);

			/* make format compatible with optimized code */
			if (r < rounds-1) {
				/* swap for next round */
				tmp = x[0];
				x[0] = x[2];
				x[2] = tmp;

				tmp = x[1];
				x[1] = x[3];
				x[3] = tmp;
			}
		}
		for (i = 0; i < BLOCK_SIZE / 32; i++) {
			/* copy out, with whitening */
			((uint32_t *)outBuffer)[i] = Bswap(
			    x[i] ^ key->subKeys[OUTPUT_WHITEN + i]);
			if (cipher->mode == MODE_CBC)
				cipher->iv32[i] = Bswap(
				    ((uint32_t *)outBuffer)[i]);
		}
	}

	return inputLen;
}

/** Decrypt blocks of data using Twofish
 *
 * The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
 * If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
 * an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block 
 * sizes can be supported.
 *
 * \param cipher	Pointer to already initialized cipherInstance
 * \param key		Pointer to already initialized keyInstance
 * \param input		Pointer to data blocks to be decrypted
 * \param inputLen	Number of bits to encrypt (multiple of blockSize)
 * \param outBuffer	Pointer to where to put decrypted blocks
 * \return		Number of bits ciphered (>=0), else error code
 */
int blockDecrypt(cipherInstance *cipher, keyInstance *key,
    const uint8_t *input, int inputLen, uint8_t *outBuffer)
{
	uint32_t	x[BLOCK_SIZE / 32];	/* block being decrypted */
	uint32_t	t0, t1;			/* temps */
	int		i, n, r;		/* loop vars */
	int		rounds = key->numRounds;
	uint8_t		bit, ctBit, carry;	/* temps for CFB */

	if (cipher->mode == MODE_CFB1) {
		/* use blockEncrypt here to handle CFB, one block at a time */

		/* do encryption in ECB */
		cipher->mode = MODE_ECB;
		for (n = 0; n < inputLen; n++) {
			blockEncrypt(cipher, key, cipher->IV, BLOCK_SIZE,
			    (uint8_t *)x);
			bit = 0x80 >> (n & 7);
			ctBit = input[n / 8] & bit;
			outBuffer[n / 8] = (outBuffer[n / 8] & ~bit) |
			    (ctBit ^ (*(uint8_t *)x & 0x80) >> (n & 7));
			carry = ctBit >> (7 - (n & 7));
			for (i = BLOCK_SIZE / 8 - 1; i >= 0; i--) {
				/* save next 'carry' bit from shift */
				bit = cipher->IV[i] >> 7;
				cipher->IV[i] = cipher->IV[i] << 1 ^ carry;
				carry = bit;
			}
		}
		/* restore mode for next time */
		cipher->mode = MODE_CFB1;
		return inputLen;
	}

	/* here for ECB, CBC modes */
	for (n = 0; n < inputLen;
	    n += BLOCK_SIZE,
	    input += BLOCK_SIZE / 8,
	    outBuffer += BLOCK_SIZE / 8) {

		/* copy in the block, add whitening */
		for (i = 0; i < BLOCK_SIZE / 32; i++)
			x[i] = Bswap(((uint32_t *)input)[i]) ^
			    key->subKeys[OUTPUT_WHITEN + i];

		/* main Twofish decryption loop */
		for (r = rounds - 1; r >= 0; r--) {
			t0 = f32(    x[0]    , key->sboxKeys, key->keyLen);
			t1 = f32(ROL(x[1], 8), key->sboxKeys, key->keyLen);

			x[2]  = ROL(x[2], 1);
			/* PHT, round keys */
			x[2] ^= t0 + t1 +
			    key->subKeys[ROUND_SUBKEYS+2*r  ];
			x[3] ^= t0 + 2 * t1 +
			    key->subKeys[ROUND_SUBKEYS+2*r+1];
			x[3]  = ROR(x[3],1);

			if (r) {
				/* unswap, except for last round */
				t0 = x[0];
				x[0]= x[2];
				x[2] = t0;

				t1 = x[1];
				x[1]= x[3];
				x[3] = t1;
			}
		}

		for (i = 0; i < BLOCK_SIZE / 32; i++) {
			/* copy out, with whitening */
			x[i] ^= key->subKeys[INPUT_WHITEN + i];
			if (cipher->mode == MODE_CBC) {
				x[i] ^= cipher->iv32[i];
				cipher->iv32[i] = Bswap(
				    ((uint32_t *)input)[i]);
			}
			((uint32_t *)outBuffer)[i] = Bswap(x[i]);
		}
	}

	return inputLen;
}
