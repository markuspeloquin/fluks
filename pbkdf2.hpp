#ifndef PBKDF2_HPP
#define PBKDF2_HPP

#include <stdint.h>

#include <stdexcept>
#include <string>

#include "luks.hpp"

namespace luks {

/** Password-Based Key Derivation Function v2
 *
 * PBKDF2 computes a special type of hash.  It's defined by PKCS #5 v2.0,
 * RFC 2898.
 *
 * \param[in] type	The hash algorithm.
 * \param[in] in	The data to hash.
 * \param[in] sz_in	The size of <code>in</code> in bytes.
 * \param[in] salt	To taste.
 * \param[in] iterations	In a sense, this is how many times you hit
 *	'blend'.
 * \param[out] derived_key	The digest.
 * \param[in] sz_key	The size of <code>derived_key</code> in bytes.
 * \param[in] benchmark	Set to true to benchmark the algorithm.
 * \return	If <code>benchmark</code> is true, the time spent (in
 *	microseconds) is returned.  Otherwise you get a magical number.
 */
uint32_t	pbkdf2(enum hash_type type, const uint8_t *in, uint32_t sz_in,
		    const uint8_t salt[SZ_SALT], uint32_t iterations,
		    uint8_t *derived_key, uint32_t sz_key,
		    bool benchmark=false);

}

#endif
