#ifndef FLUKS_SUPPORT_HPP
#define FLUKS_SUPPORT_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "cipher_spec.hpp"

namespace fluks {
namespace block_mode_info {

	block_mode	type(std::string_view mode);
	std::vector<block_mode>	types();
	std::string	name(block_mode mode);
	uint16_t	version(block_mode mode);

}

namespace iv_mode_info {

	iv_mode		type(std::string_view name);
	std::vector<iv_mode>	types();
	std::string	name(iv_mode mode);
	uint16_t	version(iv_mode mode);

}
}

#endif
