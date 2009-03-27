/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef FLUKS_SUPPORT_HPP
#define FLUKS_SUPPORT_HPP

#include <string>
#include <vector>

#include "luks.hpp"

namespace fluks {
namespace hash_info {

	/** Get the type of a hash given a name.
	 *
	 * \param	The name of the hash algorithm.
	 * \return	The type of the hash or \link HT_UNDEFINED\endlink.
	 */
	enum hash_type		type(const std::string &);

	std::vector<enum hash_type> types();

	/** Get the name of a hash in a format the kernel will recognize.
	 *
	 * \param type	The hash algorithm.
	 * \return	The kernel name of the hash, or "" if the hash
	 *	does not exist.
	 */
	const std::string	&name(enum hash_type type);

	/** Get the kernel name of the given hash name.
	 *
	 * \param type	The hash algorithm.
	 * \return	The kernel name of the hash, or "" if the hash
	 *	does not exist.
	 */
	inline std::string	canonize(const std::string &n)
	{
		enum hash_type t = type(n);
		return t == HT_UNDEFINED ? n : name(t);
	}

	/** Get the size of a hash's digest.
	 *
	 * \param type	The hash algorithm.
	 * \return	The size of the hash's digest in bytes, or 0 if
	 *	the hash does not exist.
	 */
	size_t			digest_size(enum hash_type type);

	/** Get the block size of a hash.
	 *
	 * \param type	The hash algorithm.
	 * \return	The block size of the hash in bytes, or 0 if the hash
	 *	does not exist.
	 */
	size_t			block_size(enum hash_type type);

	/** Which version of LUKS is this a part of
	 *
	 * \param typo	The hash algorithm
	 * \retval 0	The hash algorithm isn't a part of any standard
	 */
	uint16_t		version(enum hash_type type);

} namespace block_mode_info {

	enum block_mode		type(const std::string &mode);
	std::vector<enum block_mode> types();
	const std::string	&name(enum block_mode mode);
	uint16_t		version(enum block_mode mode);

} namespace iv_mode_info {

	enum iv_mode		type(const std::string &name);
	std::vector<enum iv_mode> types();
	const std::string	&name(enum iv_mode mode);
	uint16_t		version(enum iv_mode mode);

}
}

#endif
