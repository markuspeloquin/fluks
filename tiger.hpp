#ifndef TIGER_HPP
#define TIGER_HPP

#include <stdint.h>

#include <cstddef>

namespace luks {

const size_t TIGER_SZ_BLOCK = 64;
const size_t TIGER128_SZ_DIGEST = 16;
const size_t TIGER160_SZ_DIGEST = 20;
const size_t TIGER_SZ_DIGEST = 24;

/** Context structure for the Tiger hash function */
struct tiger_ctx {
	uint8_t		buf[TIGER_SZ_BLOCK];
	uint64_t	res[3];
	uint64_t	length;
	size_t		sz;
	int		passes;
};

/** Initializes the context structure
 *
 * This function should be called before each hash computation.
 *
 * \param ctx	The hash context.
 * \param passes	The number of passes to take on the data.
 */
void	tiger_init(struct tiger_ctx *ctx, int passes=3);

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
 */
void	tiger_end(struct tiger_ctx *ctx, uint8_t res[TIGER_SZ_DIGEST]);

}

#endif
