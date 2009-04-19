#ifndef SERPENT_BITS_H
#define SERPENT_BITS_H

#include <features.h>
#ifdef __cplusplus
#	include <tr1/cstdint>
#else
#	include <stdint.h>
#endif

__BEGIN_DECLS

void	sbox(uint8_t which, const uint32_t in[4], uint32_t out[4]);
void	sbox_inv(uint8_t which, const uint32_t in[4], uint32_t out[4]);

__END_DECLS

#endif
