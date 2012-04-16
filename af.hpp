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

#ifndef FLUKS_AF_HPP
#define FLUKS_AF_HPP

#include <cstdint>

#include "luks.hpp"

namespace fluks {

/** Anti-forensic split.
 *
 * Expands the input to add <em>loads</em> of entropy. Reversed by af_merge().
 * The default stripes value for AF splits in LUKS version 1 is
 * <code>NUM_STRIPES</code>.
 *
 * \param[in] in	The data to expand.
 * \param[in] sz	The size of the <code>in</code> in bytes.
 * \param[in] stripes	The number of strips to expand the data to.
 * \param[in] type	The type of hash to use.
 * \param[out] out	The output buffer, which is assumed to be of size
 *	<code>(sz * stripes)</code> bytes.
 */
void	af_split(const uint8_t *in, size_t sz, size_t stripes,
	    enum hash_type type, uint8_t *out);

/** Anti-forensic merge.
 *
 * The inverse of af_split().
 *
 * \param[in] in	The data to reduce, assumed to be of size
 *	<code>(sz * stripes)</code> bytes.
 * \param[in] sz	The size of <code>out</code> in bytes.
 * \param[in] stripes	The number of strips to expand the data to.
 * \param[in] type	The type of hash to use.
 * \param[out] out	The output buffer.
 */
void	af_merge(const uint8_t *in, size_t sz, size_t stripes,
	    enum hash_type type, uint8_t *out);

}

#endif
