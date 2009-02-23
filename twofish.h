#ifndef TWOFISH_H
#define TWOFISH_H

#include <stdbool.h>
#include <stdint.h>

#define BLOCK_SIZE	128	/* number of bits per block */

#define REENTRANT	1
#define MAX_IV_SIZE	16	/* # of bytes needed to represent an IV */
#define MAX_KEY_SIZE	64	/* # of ASCII chars needed to represent a key */
#define MAX_KEY_BITS	256	/* max number of bits of key */
#define MAX_ROUNDS	16	/* max # rounds (for allocating subkey array) */

#define INPUT_WHITEN	0	/* subkey array indices */
#define OUTPUT_WHITEN	(INPUT_WHITEN + BLOCK_SIZE/32)
#define ROUND_SUBKEYS	(OUTPUT_WHITEN + BLOCK_SIZE/32)	/* use 2 * (# rounds) */
#define TOTAL_SUBKEYS	(ROUND_SUBKEYS + 2 * MAX_ROUNDS)

#define MODE_ECB 	1 	/* Are we ciphering in ECB mode? */
#define MODE_CBC 	2 	/* Are we ciphering in CBC mode? */
#define MODE_CFB1 	3	/* Are we ciphering in 1-bit CFB mode? */

typedef struct {
	uint8_t direction;	/* Key used for encrypting or decrypting? */
	uint8_t dummyAlign[3];	/* keep 32-bit alignment */
	int keyLen;		/* Length of the key */
	char keyMaterial[MAX_KEY_SIZE + 4];/* Raw key data in ASCII */

	/* Twofish-specific parameters: */
	uint32_t keySig;	/* set to VALID_SIG by makeKey() */
	int numRounds;		/* number of rounds in cipher */
	uint32_t key32[MAX_KEY_BITS / 32];	/* actual key bits, in dwords */
	uint32_t sboxKeys[MAX_KEY_BITS / 64];	/* key bits used for S-boxes */
	uint32_t subKeys[TOTAL_SUBKEYS];	/* round subkeys, input/output whitening bits */
#if REENTRANT
	uint32_t sBox8x32[4][256];	/* fully expanded S-box */
#endif
} keyInstance;

/* The structure for cipher information */
typedef struct {
	uint8_t  mode;			/* MODE_ECB, MODE_CBC, or MODE_CFB1 */
#if ALIGN32
	uint8_t dummyAlign[3];		/* keep 32-bit alignment */
#endif
	uint8_t IV[MAX_IV_SIZE];	/* CFB1 iv bytes  (CBC uses iv32) */

	/* Twofish-specific parameters: */
	uint32_t cipherSig;		/* set to VALID_SIG by cipherInit() */
	uint32_t iv32[BLOCK_SIZE/32];	/* CBC IV bytes arranged as dwords */
} cipherInstance;

/* API to check table usage, for use in ECB_TBL KAT */
enum table_op {
	TAB_DISABLE,
	TAB_ENABLE,
	TAB_RESET,
	TAB_QUERY,
	TAB_MIN_QUERY
};

#define BAD_KEY_MAT 	-2	/* Key material not of correct length */
#define BAD_IV_MAT	-8	/* invalid IV text */

int	blockDecrypt(cipherInstance *cipher, keyInstance *key,
	    const uint8_t *input, int inputLen, uint8_t *outBuffer);

int	blockEncrypt(cipherInstance *cipher, keyInstance *key,
	    const uint8_t *input, int inputLen, uint8_t *outBuffer);

int	cipherInit(cipherInstance *cipher, uint8_t mode, const char *IV);

int	makeKey(keyInstance *key, uint8_t direction, int keyLen,
	    const char *keyMaterial);

bool	reKey(keyInstance *key);

bool	TableOp(enum table_op op);

#endif
