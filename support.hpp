/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef FLUKS_SUPPORT_HPP
#define FLUKS_SUPPORT_HPP

#include <string>
#include <vector>

#include "luks.hpp"

namespace fluks {
namespace block_mode_info {

	block_mode		type(const std::string &mode);
	std::vector<block_mode>	types();
	const std::string	&name(block_mode mode);
	uint16_t		version(block_mode mode);

}

namespace iv_mode_info {

	iv_mode			type(const std::string &name);
	std::vector<iv_mode>	types();
	const std::string	&name(iv_mode mode);
	uint16_t		version(iv_mode mode);

}
}

#endif
