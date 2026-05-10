#ifndef FLUKS_PBKDF2_HPP
#define FLUKS_PBKDF2_HPP

#include <cstdint>

#include "cipher_spec.hpp"

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
void		pbkdf2(hash_type type,
		    const uint8_t *in, uint32_t sz_in,
		    const uint8_t *salt, size_t sz_salt,
		    uint32_t iterations,
		    uint8_t *derived_key, uint32_t sz_key);

}

#endif
