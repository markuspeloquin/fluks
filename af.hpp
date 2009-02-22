#ifndef AF_HPP
#define AF_HPP

#include <stdint.h>
#include "luks.hpp"

namespace luks {

/** Anti-forensic split.
 *
 * Expands the input to add <em>loads</em> of entropy.  Reversed by
 * af_merge().  The default stripes value for AF splits in LUKS version 1 is
 * \link NUM_STRIPES\endlink.
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
 * The inverse of af_merge().
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
