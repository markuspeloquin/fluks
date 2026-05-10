#ifndef FLUKS_TIGER_H
#define FLUKS_TIGER_H

#include <features.h>

#ifdef __cplusplus
#	include <cstddef>
#	include <cstdint>
#else
#	include <stddef.h>
#	include <stdint.h>
#endif

constexpr size_t TIGER_SZ_BLOCK = 64;
constexpr size_t TIGER128_SZ_DIGEST = 16;
constexpr size_t TIGER160_SZ_DIGEST = 20;
constexpr size_t TIGER_SZ_DIGEST = 24;

/** Context structure for the Tiger hash function */
struct tiger_ctx {
	uint64_t	buf[TIGER_SZ_BLOCK/8];
	uint64_t	res[TIGER_SZ_DIGEST/8];
	uint64_t	length;
	uint8_t		sz;
	uint8_t		version;
};

#ifdef __cplusplus
extern "C" {
#endif

/** Initializes the context structure
 *
 * This function should be called before each hash computation. The version
 * number only is with regard to the padding style. The linux kernel uses
 * version 1 only.
 *
 * \param ctx		The hash context.
 * \param version	The version of Tiger (1 or 2).
 */
void	tiger_init(struct tiger_ctx *ctx, uint8_t version);

/** Update a hash with new data
 *
 * \param ctx	The hash context.
 * \param buf	The data to add.
 * \param sz	The size of the data in bytes.
 */
void	tiger_update(struct tiger_ctx *ctx, const uint8_t *buf, size_t sz);

/** End the hash computation
 *
 * \param[in] ctx	The hash context.
 * \param[out] res	The hash output.
 * \param[in] sz_res	The size of the output, one of
 *	{TIGER128_SZ_DIGEST, TIGER160_SZ_DIGEST, TIGER_SZ_DIGEST}.
 */
void	tiger_end(struct tiger_ctx *ctx, uint8_t *res, size_t sz_res);

#ifdef __cplusplus
}
#endif

#endif
