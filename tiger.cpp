#include <endian.h>
#include <stdint.h>

#include <algorithm>

#include "tiger.hpp"

extern uint64_t table[4 * 256];

// This is the official definition of 'round'.
// Passing the arguments by reference is the reason I made this file C++.
// Otherwise, registers couldn't be used (markus).
inline void
round(uint64_t &a, uint64_t &b, uint64_t &c, uint64_t x, uint8_t mul)
{
#define t1 table
#define t2 (table + 256)
#define t3 (table + 256 * 2)
#define t4 (table + 256 * 3)
	c ^= x;
	a -=
	    t1[(c >> 0 * 8) & 0xFF] ^
	    t2[(c >> 2 * 8) & 0xFF] ^
	    t3[(c >> 4 * 8) & 0xFF] ^
	    t4[(c >> 6 * 8) & 0xFF];
	b +=
	    t4[(c >> 1 * 8) & 0xFF] ^
	    t3[(c >> 3 * 8) & 0xFF] ^
	    t2[(c >> 5 * 8) & 0xFF] ^
	    t1[(c >> 7 * 8) & 0xFF];
	b *= mul;
#undef t1
#undef t2
#undef t3
#undef t4
}

inline void
tiger_compress(const uint64_t *str, int passes, uint64_t state[3])
{
	// 'register' probably gets ignored by the compiler, but it's a
	// hint from the original C89 macro-powered source
	register uint64_t a, b, c, tmpa;
	uint64_t aa, bb, cc;
	register uint64_t x0, x1, x2, x3, x4, x5, x6, x7;
	int pass_no;

	a = state[0];
	b = state[1];
	c = state[2];

	x0 = str[0];
	x1 = str[1];
	x2 = str[2];
	x3 = str[3];
	x4 = str[4];
	x5 = str[5];
	x6 = str[6];
	x7 = str[7];

	// begin old 'compress' macro

	aa = a;
	bb = b;
	cc = c;

	for (pass_no = 0; pass_no < passes; pass_no++) {
		if (pass_no) {
			// old macro 'key_schedule'
			x0 -= x7 ^ 0xA5A5A5A5A5A5A5A5LL;
			x1 ^= x0;
			x2 += x1;
			x3 -= x2 ^ (~x1 << 19);
			x4 ^= x3;
			x5 += x4;
			x6 -= x5 ^ (~x4 >> 23);
			x7 ^= x6;
			x0 += x7;
			x1 -= x0 ^ (~x7 << 19);
			x2 ^= x1;
			x3 += x2;
			x4 -= x3 ^ (~x2 >> 23);
			x5 ^= x4;
			x6 += x5;
			x7 -= x6 ^ 0x0123456789ABCDEFLL;
		}

		// old macro 'pass'
		register uint8_t mul =
		    pass_no == 0 ? 5 :
		    pass_no == 1 ? 7 : 9;
		round(a, b, c, x0, mul);
		round(b, c, a, x1, mul);
		round(c, a, b, x2, mul);
		round(a, b, c, x3, mul);
		round(b, c, a, x4, mul);
		round(c, a, b, x5, mul);
		round(a, b, c, x6, mul);
		round(b, c, a, x7, mul);

		tmpa = a;
		a = c;
		c = b;
		b = tmpa;
	}

	// old macro 'feed forward'
	a ^= aa;
	b -= bb;
	c += cc;

	// end old 'compress' macro

	state[0] = a;
	state[1] = b;
	state[2] = c;
}

void
luks::tiger_init(struct tiger_ctx *ctx, int passes)
{
	ctx->res[0] = 0x0123456789ABCDEFLL;
	ctx->res[1] = 0xFEDCBA9876543210LL;
	ctx->res[2] = 0xF096A5B4C3B2E187LL;
	ctx->length = 0;
	ctx->sz = 0;
	if (passes < 1) passes = 1;
	ctx->passes = passes;
}

void
luks::tiger_update(struct tiger_ctx *ctx, const uint8_t *buf, size_t sz)
{
	ctx->length += sz;

	if (ctx->sz + sz < TIGER_SZ_BLOCK) {
		// buffer won't fill
		std::copy(buf, buf + sz, ctx->buf + ctx->sz);
		ctx->sz += sz;
		return;
	}

	uint8_t temp[TIGER_SZ_BLOCK];

	// if data remaining in ctx
	if (ctx->sz) {
		size_t bytes = TIGER_SZ_BLOCK - ctx->sz;
		std::copy(buf, buf + bytes, ctx->buf + ctx->sz);
#if BYTE_ORDER == BIG_ENDIAN
		// switch each 64bit word from big- to little-endian
		for (size_t i = 0; i < TIGER_SZ_BLOCK ; i++)
			temp[i ^ 7] = ctx->buf[i];
		tiger_compress(reinterpret_cast<uint64_t *>(temp),
		    ctx->passes, ctx->res);
#else
		tiger_compress(reinterpret_cast<uint64_t *>(ctx->buf),
		    ctx->passes, ctx->res);
#endif
		buf += bytes;
		sz -= bytes;
		// context buffer now empty
	}

	// TODO I suppose it's possible to see if buf is at an acceptable
	// offset for 64bit integers, but I don't know what's really
	// involved in that; instead, I'll copy all the bytes
	while (sz > TIGER_SZ_BLOCK) {
#if BYTE_ORDER == BIG_ENDIAN
		for (size_t i = 0; i < TIGER_SZ_BLOCK; i++)
			temp[i ^ 7] = ctx->buf[i];
#else
		std::copy(buf, buf + TIGER_SZ_BLOCK, temp);
#endif
		tiger_compress(reinterpret_cast<uint64_t *>(temp),
		    ctx->passes, ctx->res);
		sz -= TIGER_SZ_BLOCK;
		buf += TIGER_SZ_BLOCK;
	}

	if (sz)
		// fill context buffer with the remaining bytes
		std::copy(buf, buf + sz, ctx->buf);
	ctx->sz = sz;
}

void
luks::tiger_end(struct tiger_ctx *ctx, uint8_t res[TIGER_SZ_DIGEST])
{
	uint8_t temp[TIGER_SZ_BLOCK];
	size_t i;

	// (switch endian if necessary;) copy into the context buffer 0x01,
	// then pad with zeros until the number of bytes is 0 mod 8
#if BYTE_ORDER == BIG_ENDIAN
	for (i = 0; i < ctx->sz; i++)
		temp[i ^ 7] = reinterpret_cast<const uint8_t *>(ctx->buf)[i];
	temp[i++ ^ 7] = 0x01;
	while (i & 7) temp[i++ ^ 7] = 0;
#else
	std::copy(ctx->buf, ctx->buf + ctx->sz, temp);
	i = ctx->sz;
	temp[i++] = 0x01;
	while (i & 7) temp[i++] = 0;
#endif

	// if number of bytes in temp is 64 (it is 0 mod 8, and so if it is
	// greater than 56, it can only be 64), then fill the rest of the
	// buffer with zeros and compress the block
	if (i > 56) {
		// I really doubt this loop does anything
		while (i < TIGER_SZ_BLOCK) temp[i++] = 0;
		tiger_compress(reinterpret_cast<uint64_t *>(temp),
		    ctx->passes, ctx->res);
		i = 0;
	}

	// zero out all bytes from the first unused byte (at position i) to
	// 8 before the end; length*8 is written to the final 64 bits of
	// the buffer; then compress this final buffer
	while (i < 56) temp[i++] = 0;
	reinterpret_cast<uint64_t *>(temp + 56)[0] = ctx->length << 3;
	tiger_compress(reinterpret_cast<uint64_t *>(temp),
	    ctx->passes, ctx->res);

	std::copy(ctx->res, ctx->res + 3, reinterpret_cast<uint64_t *>(res));
}

// the original implementation of tiger(), with my annotations and coding
// style inflicted upon it
#if 0
void
luks::tiger_impl(const uint8_t *str8, uint64_t length, int passes,
    uint64_t res[3])
{
	uint8_t			temp[TIGER_SZ_BLOCK];
	register uint64_t	i;
	register uint64_t	j;
	register const uint64_t *str =
	    reinterpret_cast<const uint64_t *>(str8);

	res[0] = 0x0123456789ABCDEFLL;
	res[1] = 0xFEDCBA9876543210LL;
	res[2] = 0xF096A5B4C3B2E187LL;

	// (x ^ 7) same as ((x - x%8) + (7 - x%8))
	// that is, change the number such that x%8 becomes 7-x%8; in other
	// words, pure magic

	// once for each whole 64-byte block, compress on next 64 bytes
	for (i = length; i >= TIGER_SZ_BLOCK; i -= TIGER_SZ_BLOCK) {
#if BYTE_ORDER == BIG_ENDIAN
		// switch endian to little, 8 bytes at a time
		for (j = 0; j < TIGER_SZ_BLOCK; j++)
			temp[j ^ 7] =
			    reinterpret_cast<const uint8_t *>(str)[j];
		tiger_compress(reinterpret_cast<uint64_t *>(temp),
		    passes, res);
#else
		tiger_compress(str, passes, res);
#endif
		str += 8;
	}

	// now i contains the number of bytes in the final partial block

	// copy next i bytes from str into start of temp, then 0x01, then
	// pad with zeros until the number of bytes in temp is 0 mod 8
#if BYTE_ORDER == BIG_ENDIAN
	for (j = 0; j < i; j++)
		temp[j ^ 7] = reinterpret_cast<const uint8_t *>(str)[j];
	temp[j++ ^ 7] = 0x01;
	while (j & 7) temp[j++ ^ 7] = 0;
#else
	for (j = 0; j < i; j++)
		temp[j] = reinterpret_cast<const uint8_t *>(str)[j];
	temp[j++] = 0x01;
	while (j & 7) temp[j++] = 0;
#endif

	// if number of bytes in temp is 64 (it is 0 mod 8, and so if it is
	// greater than 56, it can only be 64), then fill the rest of the
	// buffer with zeros and compress the block
	if (j > 56) {
		// I really doubt this loop does anything
		while (j < TIGER_SZ_BLOCK) temp[j++] = 0;
		tiger_compress(reinterpret_cast<uint64_t *>(temp), passes, res);
		j = 0;
	}

	// zero out all bytes from the first unused byte (at position j) to
	// 8 before the end; length*8 is written to the final 64 bits of
	// the buffer; then compress this final buffer
	while (j < 56) temp[j++] = 0;
	reinterpret_cast<uint64_t *>(temp + 56)[0] = length << 3;
	tiger_compress(reinterpret_cast<uint64_t *>(temp), passes, res);
}
#endif
