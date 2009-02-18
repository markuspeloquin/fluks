#ifndef PBKDF2_HPP
#define PBKDF2_HPP

#include <stdint.h>

#include <stdexcept>
#include <string>

#include "luks.hpp"

namespace luks {

void	pbkdf2(enum hash_type, const uint8_t *, uint32_t,
	    const uint8_t[SZ_SALT], uint32_t, uint8_t *, uint32_t);

}

#endif
