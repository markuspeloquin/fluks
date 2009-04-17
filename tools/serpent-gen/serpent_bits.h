#ifndef SERPENT_BITS_H
#define SERPENT_BITS_H

#include <stdint.h>

void	sbox(uint8_t which, const uint32_t in[4], uint32_t out[4]);
void	sbox_inv(uint8_t which, const uint32_t in[4], uint32_t out[4]);

#endif
