#ifndef UTIL_HPP
#define UTIL_HPP

#include <stdint.h>
#include <cstddef>

namespace luks {

/** XOR two buffers together.
 *
 * \param[in] a	The first operand.
 * \param[in] b The second operand.
 * \param[in] sz	The size of the buffers in bytes.
 * \param[out] c	The output buffer.  It can safely be the same as
 *	<code>a</code> or <code>b</code>.
 */
void	xor_bufs(const uint8_t *a, const uint8_t *b, size_t sz, uint8_t *c);

}

#endif
