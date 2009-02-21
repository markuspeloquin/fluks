#ifndef TIGER_HPP
#define TIGER_HPP

#include <stdint.h>

namespace luks {

void	tiger_impl(const uint8_t *str, uint64_t length, int passes,
	    uint64_t res[3]);

}

#endif
