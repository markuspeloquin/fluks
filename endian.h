/* Copyright (c) 2009-2011, Markus Peloquin <markus@cs.wisc.edu>
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

#ifndef FLUKS_ENDIAN_H
#define FLUKS_ENDIAN_H

#ifdef __cplusplus
#	include <cstddef>
#	include <cstdint>
#	include <cstring>
#else
#	include <stdbool.h>
#	include <stddef.h>
#	include <stdint.h>
#	include <string.h>
#endif

#ifdef __cplusplus
#	define FLUKS_INLINE inline
#else
#	define FLUKS_INLINE static inline
#endif

/*
 * With some testing, I discovered that this is an interesting and extremely
 * slow way of endian-switching:
 *	for (size_t i = 0; i < sz; i++)
 *		o8[i] = i8[i ^ 3];
 * Another issue is whether the input is aligned, which has a factor 5
 * difference.
 *
 * Annoyingly, clang++ (and probably g++) define _GNU_SOURCE, so all the
 * non-standard functions from endian.h needed a prefixed 'fluks_'.
 */

/** Convert a single 16-bit integer's endian */
FLUKS_INLINE uint16_t
be16tole(uint16_t x) {
	x = (x << 8) | (x >> 8);
	return x;
}

FLUKS_INLINE uint16_t
le16tobe(uint16_t x) {
	return be16tole(x);
}

FLUKS_INLINE uint16_t
fluks_htobe16(uint16_t x) {
#if FLUKS_IS_BIG_ENDIAN
	return x;
#else
	return le16tobe(x);
#endif
}

FLUKS_INLINE uint16_t
fluks_be16toh(uint16_t x) {
	return fluks_htobe16(x);
}

/** Convert a single 32-bit integer's endian */
FLUKS_INLINE uint32_t
be32tole(uint32_t x) {
	x = ((x & 0x00ff00ff) << 8) | ((x & 0xff00ff00) >> 8);
	x = (x << 16) | (x >> 16);
	return x;
}

FLUKS_INLINE uint32_t
le32tobe(uint32_t x) {
	return be32tole(x);
}

FLUKS_INLINE uint32_t
fluks_be32toh(uint32_t x) {
#if FLUKS_IS_BIG_ENDIAN
	return x;
#else
	return be32tole(x);
#endif
}

FLUKS_INLINE uint32_t
fluks_htobe32(uint32_t x) {
	return fluks_be32toh(x);
}

FLUKS_INLINE uint32_t
fluks_le32toh(uint32_t x) {
#if FLUKS_IS_BIG_ENDIAN
	return le32tobe(x);
#else
	return x;
#endif
}

FLUKS_INLINE uint32_t
fluks_htole32(uint32_t x) {
	return fluks_le32toh(x);
}

/** Convert a single 64-bit integer's endian */
FLUKS_INLINE uint64_t
be64tole(uint64_t x) {
	x = ((x & 0x00ff00ff00ff00ffULL) << 8)  | ((x & 0xff00ff00ff00ff00ULL) >> 8);
	x = ((x & 0x0000ffff0000ffffULL) << 16) | ((x & 0xffff0000ffff0000ULL) >> 16);
	x = (x << 32) | (x >> 32);
	return x;
}

FLUKS_INLINE uint64_t
le64tobe(uint64_t x) {
	return be64tole(x);
}

/** Convert a be32 array to an le32 array */
FLUKS_INLINE void
be32tole_buf(void *out, const void *in, size_t sz) {
	if (((long)out | (long)in) & 3) {
		/* at least one arg unaligned */
		const uint8_t	*i8 = (const uint8_t *)in;
		uint8_t		*o8 = (uint8_t *)out;
		uint32_t	temp;
		for (size_t i = 0; i < sz; i += 4) {
			memcpy(&temp, i8 + i, 4);
			temp = be32tole(temp);
			memcpy(o8 + i, &temp, 4);
		}
	} else {
		/* both args aligned */
		const uint32_t	*i32 = (const uint32_t *)in;
		uint32_t	*o32 = (uint32_t *)out;
		size_t		n = sz / 4;
		for (size_t i = 0; i < n; i++)
			o32[i] = be32tole(i32[i]);
	}
}

/** Convert an le32 array to a be32 array */
FLUKS_INLINE void
le32tobe_buf(void *out, const void *in, size_t sz) {
	be32tole_buf(out, in, sz);
}

/** Convert a be32 array to a host32 array */
FLUKS_INLINE void
be32toh_buf(void *out, const void *in, size_t sz) {
#if FLUKS_BIG_ENDIAN
	if (in != out) memcpy(out, in, sz);
#else
	be32tole_buf(out, in, sz);
#endif
}

/** Convert a host32 array to a be32 array */
FLUKS_INLINE void
htobe32_buf(void *out, const void *in, size_t sz) {
	be32toh_buf(out, in, sz);
}

/** Convert an le32 array to a host32 array */
FLUKS_INLINE void
le32toh_buf(void *out, const void *in, size_t sz) {
#if FLUKS_BIG_ENDIAN
	be32tole_buf(out, in, sz);
#else
	memcpy(out, in, sz);
#endif
}

/** Convert a host32 array to an le32 array */
FLUKS_INLINE void
htole32_buf(void *out, const void *in, size_t sz) {
	le32toh_buf(out, in, sz);
}

/** Convert a be64 array to an le64 array */
FLUKS_INLINE void
be64tole_buf(void *out, const void *in, size_t sz) {
	if (((long)out | (long)in) & 7) {
		/* at least one arg unaligned */
		const uint8_t	*i8 = (const uint8_t *)in;
		uint8_t		*o8 = (uint8_t *)out;
		uint64_t	temp;
		for (size_t i = 0; i < sz; i += 8) {
			memcpy(&temp, i8 + i, 8);
			temp = be64tole(temp);
			memcpy(o8 + i, &temp, 8);
		}
	} else {
		/* both args aligned */
		const uint64_t	*i64 = (const uint64_t *)in;
		uint64_t	*o64 = (uint64_t *)out;
		size_t		n = sz / 8;
		for (size_t i = 0; i < n; i++)
			o64[i] = be64tole(i64[i]);
	}
}

/** Convert a be64 array to an le64 array */
FLUKS_INLINE void
le64tobe_buf(void *out, const void *in, size_t sz) {
	be64tole_buf(out, in, sz);
}

/** Convert an le64 array to a host64 array */
FLUKS_INLINE void
le64toh_buf(void *out, const void *in, size_t sz) {
#if FLUKS_BIG_ENDIAN
	be64tole_buf(out, in, sz);
#else
	memcpy(out, in, sz);
#endif
}

/** Convert a host64 array to an le64 array */
FLUKS_INLINE void
htole64_buf(void *out, const void *in, size_t sz) {
	le64toh_buf(out, in, sz);
}

/** Convert a be64 array to a host64 array */
FLUKS_INLINE void
be64toh_buf(void *out, const void *in, size_t sz) {
#if FLUKS_BIG_ENDIAN
	memcpy(out, in, sz);
#else
	be64tole_buf(out, in, sz);
#endif
}

/** Convert a host64 array to a be64 array */
FLUKS_INLINE void
htobe64_buf(void *out, const void *in, size_t sz) {
	be64toh_buf(out, in, sz);
}

#undef FLUKS_INLINE

#endif
