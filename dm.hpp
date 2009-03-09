#ifndef DM_HPP
#define DM_HPP

#include <stdint.h>

#include <cstddef>
#include <string>

#include "errors.hpp"

namespace luks {

void	dm_create(const std::string &name, uint64_t start_sector,
	    uint64_t num_sectors, const std::string &cipher_spec,
	    const uint8_t *key, size_t sz_key, const std::string &device_path)
	    throw (Dm_error);
}

#endif
