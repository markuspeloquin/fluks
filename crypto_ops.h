#ifndef FLUKS_CRYPTO_OPS_H
#define FLUKS_CRYPTO_OPS_H

#include <features.h>

#ifdef __cplusplus
#	include <cstdint>
#	define FLUKS_INLINE inline
#else
#	include <stdint.h>
#	define FLUKS_INLINE static inline
#endif

/** Rotate left. */
FLUKS_INLINE uint32_t
ROL(uint32_t x, int n) {
	return x << n | x >> (32 - n);
}

/** Rotate right. */
FLUKS_INLINE uint32_t
ROR(uint32_t x, int n) {
	return x << (32 - n) | x >> n;
}

#undef FLUKS_INLINE

#endif
