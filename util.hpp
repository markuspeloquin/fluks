#ifndef FLUKS_UTIL_HPP
#define FLUKS_UTIL_HPP

#include <cstddef>
#include <cstdint>

namespace fluks {

/** XOR two buffers together.
 *
 * \param[in] a	The first operand.
 * \param[in] b The second operand.
 * \param[in] sz	The size of the buffers in bytes.
 * \param[out] c	The output buffer. It can safely be the same as
 *	<code>a</code> or <code>b</code>.
 */
inline void	xor_bufs(const uint8_t *a, const uint8_t *b, size_t sz,
		    uint8_t *c);

/** XOR each byte of a buffer with a single byte.
 *
 * \param[in] a		The buffer
 * \param[in] sz	The size of the input/output buffers
 * \param[in] b		The byte to XOR with the first buffer
 * \param[out] c	The output buffer. It can safely be the same as
 *	<code>a</code>.
 */
inline void	xor_buf_byte(const uint8_t *a, size_t sz, uint8_t b,
		    uint8_t *c);

inline void
xor_bufs(const uint8_t *a, const uint8_t *b, size_t sz, uint8_t *c) {
	while (sz--) *c++ = *a++ ^ *b++;
}

inline void
xor_buf_byte(const uint8_t *a, size_t sz, uint8_t b, uint8_t *c) {
	while (sz--) *c++ = *a++ ^ b;
}

}

#endif
