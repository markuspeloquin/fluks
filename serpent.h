#ifndef FLUKS_SERPENT_H
#define FLUKS_SERPENT_H

#include <features.h>

#ifdef __cplusplus
#	include <cstddef>
#	include <cstdint>
#else
#	include <stddef.h>
#	include <stdint.h>
#endif

constexpr size_t SERPENT_BLOCK = 16;
constexpr size_t SERPENT_KEYMIN = 16;
constexpr size_t SERPENT_KEYMAX = 32;
constexpr size_t SERPENT_KEYSTEP = 8;

enum serpent_return {
	/** Key material not of correct length */
	SERPENT_BAD_KEY_MAT = -1,
	SERPENT_OKAY = 0
};

struct serpent_ctx {
	uint32_t	subkeys[33][4];
};

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize a Serpent context.
 *
 * \param ctx	The context structure.
 * \param key	The key, big endian byte order.
 * \param sz	The size of the key in bytes.
 * \retval SERPENT_BAD_KEY_MAT	The key size is invalid.
 */
[[nodiscard]] enum serpent_return
	serpent_init(struct serpent_ctx *ctx,
	    const uint8_t *key, size_t sz);

/** Encrypt a block of data.
 *
 * \param[in] ctx		The context structure.
 * \param[out] plaintext	The data to encrypt, big endian order.
 * \param[out] ciphertext	The encrypted data, big endian order.
 */
void	serpent_encrypt(const struct serpent_ctx *ctx,
	    const uint8_t plaintext[SERPENT_BLOCK],
	    uint8_t ciphertext[SERPENT_BLOCK]);

/** Decrypt a block of data.
 *
 * \param[in] ctx		The context structure.
 * \param[out] ciphertext	The data to decrypt, big endian order.
 * \param[out] plaintext	The decrypted data, big endian order.
 */
void	serpent_decrypt(const struct serpent_ctx *ctx,
	    const uint8_t ciphertext[SERPENT_BLOCK],
	    uint8_t plaintext[SERPENT_BLOCK]);

#ifdef __cplusplus
}
#endif

#endif
