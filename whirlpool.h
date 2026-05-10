#ifndef FLUKS_WHIRLPOOL_H
#define FLUKS_WHIRLPOOL_H

#include <features.h>

#ifdef __cplusplus
#	include <cstddef>
#	include <cstdint>
#else
#	include <stddef.h>
#	include <stdint.h>
#endif

constexpr size_t WHIRLPOOL256_SZ_DIGEST = 32;
constexpr size_t WHIRLPOOL384_SZ_DIGEST = 48;
constexpr size_t WHIRLPOOL_SZ_DIGEST = 64;
constexpr size_t WHIRLPOOL_SZ_BLOCK = 64;

struct whirlpool_ctx {
	/* the hashing state */
	uint64_t	hash[WHIRLPOOL_SZ_DIGEST / 8];

	/* global number of hashed bits (256-bit counter) */
	uint32_t	bit_count[8];

	/* buffer of data to hash */
	uint8_t		buf[WHIRLPOOL_SZ_BLOCK];

	/* position in 'buf' */
	uint8_t		pos;
};

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize/reset a whirlpool context.
 * \param ctx	The context.
 */
void	whirlpool_init(struct whirlpool_ctx *ctx);

/** Add append data to the data being hashed.
 * \param ctx	The context.
 * \param buf	The data to be appended (big endian).
 * \param sz	The size of the data in bytes.
 */
void	whirlpool_update(struct whirlpool_ctx *ctx,
	    const uint8_t *buf, size_t sz);

/** Mark the end of the hashed data and return the digest.
 * \param[in] ctx	The context.
 * \param[out] buf	The destination buffer of the digest.
 * \param[in] sz_buf	The size of the output buffer. Should be one of
 *	{WHIRLPOOL256_SZ_DIGEST, WHIRLPOOL384_SZ_DIGEST, WHIRLPOOL_SZ_DIGEST}.
 */
void	whirlpool_end(struct whirlpool_ctx *ctx, uint8_t *buf, size_t sz_buf);

#ifdef __cplusplus
}
#endif

#endif
