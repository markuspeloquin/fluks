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

#ifndef FLUKS_PBKDF2_HPP
#define FLUKS_PBKDF2_HPP

#include <cstdint>
#include <stdexcept>
#include <string>

#include "errors.hpp"
#include "luks.hpp"

namespace fluks {

/** Password-Based Key Derivation Function v2
 *
 * PBKDF2 computes a special type of hash. It's defined by PKCS #5 v2.0,
 * RFC 2898.
 *
 * \param[in] type	The hash algorithm.
 * \param[in] in	The data to hash.
 * \param[in] sz_in	The size of <code>in</code> in bytes.
 * \param[in] salt	To taste.
 * \param[in] sz_salt	Size of <code>salt</code> in bytes.
 * \param[in] iterations	In a sense, this is how many times you hit
 *	'blend'.
 * \param[out] derived_key	The digest.
 * \param[in] sz_key	The size of <code>derived_key</code> in bytes.
 * \throw Bad_spec	<code>type</code> is invalid.
 */
void		pbkdf2(enum hash_type type,
		    const uint8_t *in, uint32_t sz_in,
		    const uint8_t *salt, size_t sz_salt,
		    uint32_t iterations,
		    uint8_t *derived_key, uint32_t sz_key)
		    throw (Bad_spec);

}

#endif
