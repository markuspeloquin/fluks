#ifndef FLUKS_WHIRLPOOL_H
#define FLUKS_WHIRLPOOL_H

#include <features.h>
#include <stdint.h>

#ifdef __cplusplus
// C++
#include <cstddef>

namespace fluks {

// because I hate macros
const size_t WHIRLPOOL256_SZ_DIGEST = 32;
const size_t WHIRLPOOL384_SZ_DIGEST = 48;
const size_t WHIRLPOOL_SZ_DIGEST = 64;
const size_t WHIRLPOOL_SZ_BLOCK = 64;

#else 
/* C */
#	define WHIRLPOOL_SZ_DIGEST	64
#	define WHIRLPOOL_SZ_BLOCK	64
#endif


/* for internal use */
#define LENGTHBYTES 32

struct whirlpool_ctx {
	/* global number of hashed bits (256-bit counter) */
	uint8_t  bitLength[LENGTHBYTES];

	/* buffer of data to hash */
	uint8_t  buffer[WHIRLPOOL_SZ_BLOCK];

	/* current number of bits on the buffer */
	int bufferBits;

	/* current (possibly incomplete) byte slot on the buffer */
	int bufferPos;

	/* the hashing state */
	uint64_t hash[WHIRLPOOL_SZ_DIGEST / sizeof(uint64_t)];
};

__BEGIN_DECLS

void	whirlpool_init(struct whirlpool_ctx *const ctx);
void	whirlpool_update(struct whirlpool_ctx *const ctx,
	    const uint8_t *const buf, size_t sz);
void	whirlpool_end(struct whirlpool_ctx *const ctx, uint8_t *const buf);

__END_DECLS

#ifdef __cplusplus
} // namespace fluks
#endif

/* it gets redefined in whirlpool.c */
#undef LENGTHBYTES

#endif
