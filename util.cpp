#include "util.hpp"

// compute a ^ b, store in c; it does not matter if any of the following 
// are true: a=b, a=c, b=c, a=b=c
void
fluks::xor_bufs(const uint8_t *a, const uint8_t *b, size_t sz, uint8_t *c)
{
	const uint64_t	*a64 = reinterpret_cast<const uint64_t *>(a);
	const uint64_t	*b64 = reinterpret_cast<const uint64_t *>(b);
	uint64_t	*c64 = reinterpret_cast<uint64_t *>(c);
	size_t		whole = sz / 8;

	// 8 bytes at a time should be more efficient, probably even on
	// 32-bit systems
	while (whole--)
		*c64++ = *a64++ ^ *b64++;

	size_t offset = sz / 8 * 8;
	sz -= offset;
	a += offset;
	b += offset;
	c += offset;

	while (sz--)
		*c++ = *a++ ^ *b++;
}

void
fluks::xor_buf_byte(const uint8_t *a, size_t sz, uint8_t b, uint8_t *c)
{
	const uint64_t	*a64 = reinterpret_cast<const uint64_t *>(a);
	uint64_t	*c64 = reinterpret_cast<uint64_t *>(c);
	uint64_t	b64 = b;
	size_t		whole = sz / 8;
	size_t		offset = whole * 8;

	b64 |= b64 << 8;
	b64 |= b64 << 16;
	b64 |= b64 << 32;

	while (whole--)
		*c64++ = *a64++ ^ b64;

	sz -= offset;
	a += offset;
	c += offset;

	while (sz--)
		*c++ = *a++ ^ b;
}
