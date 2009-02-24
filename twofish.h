#ifndef TWOFISH_H
#define TWOFISH_H

#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>

#define BLOCK_SIZE	16	/* number of bytes per block */

#define REENTRANT	1
#define MAX_IV_SIZE	16	/* # of bytes needed to represent an IV */
#define MAX_SZ_AKEY	64	/* bytes for hex representation */
#define MIN_SZ_KEY	16	/* bytes */
#define MAX_SZ_KEY	32	/* bytes */
#define MAX_ROUNDS	16	/* max # rounds (for allocating subkey array) */

#define INPUT_WHITEN	0	/* subkey array indices */
#define OUTPUT_WHITEN	(INPUT_WHITEN + BLOCK_SIZE / 4)
#define ROUND_SUBKEYS	(OUTPUT_WHITEN + BLOCK_SIZE / 4)	/* use 2 * (# rounds) */
#define TOTAL_SUBKEYS	(ROUND_SUBKEYS + 2 * MAX_ROUNDS)

#define MODE_ECB 	1 	/* Are we ciphering in ECB mode? */
#define MODE_CBC 	2 	/* Are we ciphering in CBC mode? */
#define MODE_CFB1 	3	/* Are we ciphering in 1-bit CFB mode? */

struct twofish_key {
#if REENTRANT
	uint32_t sBox8x32[4][256];	/* fully expanded S-box */
#endif
	uint32_t key32[MAX_SZ_KEY / 4];
	uint32_t sboxKeys[MAX_SZ_KEY / 8];	/* key bytes used for S-boxes */
	uint32_t subKeys[TOTAL_SUBKEYS];	/* round subkeys, input/output whitening bits */
	char keyMaterial[MAX_SZ_AKEY + 4];/* Raw key data in ASCII */

	uint32_t keySig;	/* set to VALID_SIG by make_key() */
	size_t sz_key;		/* Length of the key in bytes */
	unsigned numRounds;	/* number of rounds in cipher */
};

/* The structure for cipher information */
struct twofish_cipher {
	uint8_t  mode;			/* MODE_ECB, MODE_CBC, or MODE_CFB1 */
#if ALIGN32
	uint8_t dummyAlign[3];		/* keep 32-bit alignment */
#endif
	uint8_t IV[MAX_IV_SIZE];	/* CFB1 iv bytes  (CBC uses iv32) */

	/* Twofish-specific parameters: */
	uint32_t cipherSig;		/* set to VALID_SIG by cipherInit() */
	uint32_t iv32[BLOCK_SIZE / 4];	/* CBC IV bytes arranged as dwords */
};

/* API to check table usage, for use in ECB_TBL KAT */
enum table_op {
	TAB_DISABLE,
	TAB_ENABLE,
	TAB_RESET,
	TAB_QUERY,
	TAB_MIN_QUERY
};

#define BAD_ALIGN	-1	/**< Alignment of argument was off */
#define BAD_CIPHER_MODE	-2
#define BAD_IV_MAT	-3	/**< Invalid IV text */
/** Either a bad size or too many 'subkeys' */
#define BAD_KEY_INSTANCE	-4
#define BAD_KEY_MAT 	-5	/**< Key material not of correct length */
#define BAD_PARAMS	-6	/**< NULL argument usually */

/** Decrypt blocks of data using Twofish
 *
 * The only supported block size for ECB/CBC modes is BLOCK_SIZE bytes.
 * If inputLen is not a multiple of BLOCK_SIZE bytes in those modes,
 * an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block 
 * sizes can be supported.
 *
 * \param cipher	Cipher instance
 * \param key		Key instance
 * \param input		Data blocks to be decrypted
 * \param sz_in		Number of bytes to encrypt (multiple of BLOCK_SIZE)
 * \param outBuffer	Pointer to where to put decrypted blocks
 * \return		Number of bytes ciphered (>=0), else error code
 */
ssize_t	twofish_decrypt(struct twofish_cipher *cipher, struct twofish_key *key,
	    const uint8_t *input, size_t sz_in, uint8_t *outBuffer);

/** Encrypt block(s) of data using Twofish
 *
 * The only supported block size for ECB/CBC modes is BLOCK_SIZE bytes.
 * If inputLen is not a multiple of BLOCK_SIZE bytes in those modes,
 * an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block 
 * sizes can be supported.
 *
 * \param cipher	Pointer to already initilaized struct twofish_cipher
 * \param key		Pointer to already initialized struct twofish_key
 * \param input		Pointer to data blocks to be encrypted
 * \param sz_in		Number of bytes to encrypt (multiple of BLOCK_SIZE)
 * \param outBuffer	Pointer to where to put encrypted blocks
 * \return		Number of bytes ciphered (>=0), else error code
 */
ssize_t	twofish_encrypt(struct twofish_cipher *cipher,
	    struct twofish_key *key, const uint8_t *input, size_t sz_in,
	    uint8_t *outBuffer);

/** Initialize the Twofish cipher in a given mode
 *
 * \param cipher	Pointer to cipherINstance to be initialized
 * \param mode		MODE_ECB or MODE_CBC or MODE_CFB1
 * \param IV		Hex ASCII text representing IV bytes
 * \return		1 on success, else error code
 */
int	cipherInit(struct twofish_cipher *cipher, uint8_t mode,
	    const char *IV);

/** Handle table use checking
 *
 * This routine is for use in generating the tables KAT file.
 *
 * \param op	What to do (see TAB_* defines in aes.h)
 * \return	True iff done (for TAB_QUERY)
 */
bool	do_table_op(enum table_op op);

/** Initialize the Twofish key schedule
 *
 * This parses the key bits from keyMaterial.  No crypto stuff happens here.
 * The function re_key() is called to actually build the key schedule after
 * the keyMaterial has been parsed.
 *
 * \param key		Pointer to struct twofish_key to be initialized
 * \param sz_key	Number of bytes of key text at *keyMaterial.
 * \param keyMaterial	Pointer to hex ASCII chars representing key bits.
 * \return		1 iff success, else error code
 */
int	make_key(struct twofish_key *key, int sz_key, const char *keyMaterial);

#endif
