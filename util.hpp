#ifndef UTIL_HPP
#define UTIL_HPP

#include <stdint.h>
#include <cstddef>

namespace luks {

void	xor_bufs(const uint8_t *, const uint8_t *, size_t, uint8_t *);

}

#endif
