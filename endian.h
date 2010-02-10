/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef FLUKS_ENDIAN_H
#define FLUKS_ENDIAN_H

#include <endian.h>

#ifdef __cplusplus
#	include <cassert>
#	include <cstddef>
#	include <cstring>
#	include <tr1/cstdint>
#else
#	include <assert.h>
#	include <stddef.h>
#	include <stdint.h>
#	include <string.h>
#endif

#ifndef BYTE_ORDER
#	error "BYTE_ORDER not defined, is _BSD_SOURCE defined?"
#endif
#ifndef BIG_ENDIAN
#	error "BIG_ENDIAN not defined, is _BSD_SOURCE defined?"
#endif
#ifndef LITTLE_ENDIAN
#	error "LITTLE_ENDIAN not defined, is _BSD_SOURCE defined?"
#endif

#ifdef __cplusplus
#	define INLINE inline
#else
#	define INLINE static inline
#endif

/*
 * With some testing, I discovered that this is an interesting and extremely
 * slow way of endian-switching:
 *	for (size_t i = 0; i < sz; i++)
 *		o8[i] = i8[i ^ 3];
 * Another issue is whether the input is aligned, which has a factor 5
 * difference.
 */

/** Convert a single 32-bit integer's endian */
INLINE uint32_t
betole32(uint32_t x)
{
#if BYTE_ORDER == BIG_ENDIAN
	return htole32(x);
#else
	return htobe32(x);
#endif
}

/** Convert a be32 array to an le32 array */
INLINE void
be_to_le32(void *out, const void *in, size_t sz)
{
	size_t	n = sz / 4;
	if (((int)out | (int)in) & 3) {
		/* at least one arg unaligned */
		const uint8_t	*i8 = (const uint8_t *)in;
		uint8_t		*o8 = (uint8_t *)out;
		uint32_t	temp;
		for (size_t i = 0; i < n; i++) {
			size_t	off = i * 4;
			memcpy(&temp, i8 + off, 4);
			temp = betole32(temp);
			memcpy(o8 + off, &temp, 4);
		}
	} else {
		/* both args aligned */
		const uint32_t	*i32 = (const uint32_t *)in;
		uint32_t	*o32 = (uint32_t *)out;
		for (size_t i = 0; i < n; i++)
			o32[i] = betole32(i32[i]);
	}
}

/** Convert an le32 array to a be32 array */
INLINE void
le_to_be32(void *out, const void *in, size_t sz)
{	be_to_le32(out, in, sz); }

/** Convert a be32 array to a host32 array */
INLINE void
be_to_host32(void *out, const void *in, size_t sz)
{
#if BYTE_ORDER == BIG_ENDIAN
	memcpy(out, in, sz);
#else
	be_to_le32(out, in, sz);
#endif
}

/** Convert a host32 array to a be32 array */
INLINE void
host_to_be32(void *out, const void *in, size_t sz)
{	be_to_host32(out, in, sz); }

/** Convert an le32 array to a host32 array */
INLINE void
le_to_host32(void *out, const void *in, size_t sz)
{
#if BYTE_ORDER == BIG_ENDIAN
	be_to_le32(out, in, sz);
#else
	memcpy(out, in, sz);
#endif
}

/** Convert a host32 array to an le32 array */
INLINE void
host_to_le32(void *out, const void *in, size_t sz)
{	le_to_host32(out, in, sz); }

/** Convert a single 64-bit integer's endian */
INLINE uint64_t
betole64(uint64_t x)
{
#if BYTE_ORDER == BIG_ENDIAN
	return htole64(x);
#else
	return htobe64(x);
#endif
}

/** Convert a be64 array to an le64 array */
INLINE void
be_to_le64(void *out, const void *in, size_t sz)
{
	size_t	n = sz / 8;
	if (((int)out | (int)in) & 7) {
		/* at least one arg unaligned */
		const uint8_t	*i8 = (const uint8_t *)in;
		uint8_t		*o8 = (uint8_t *)out;
		uint64_t	temp;
		for (size_t i = 0; i < n; i++) {
			size_t	off = i * 8;
			memcpy(&temp, i8 + off, 8);
			temp = betole64(temp);
			memcpy(o8 + off, &temp, 8);
		}
	} else {
		/* both args aligned */
		const uint64_t	*i64 = (const uint64_t *)in;
		uint64_t	*o64 = (uint64_t *)out;
		for (size_t i = 0; i < n; i++)
			o64[i] = betole64(i64[i]);
	}
}

/** Convert a be64 array to an le64 array */
INLINE void
le_to_be64(void *out, const void *in, size_t sz)
{	be_to_le64(out, in, sz); }

/** Convert an le64 array to a host64 array */
INLINE void
le_to_host64(void *out, const void *in, size_t sz)
{
#if BYTE_ORDER == BIG_ENDIAN
	be_to_le64(out, in, sz);
#else
	memcpy(out, in, sz);
#endif
}

/** Convert a host64 array to an le64 array */
INLINE void
host_to_le64(void *out, const void *in, size_t sz)
{	le_to_host64(out, in, sz); }

/** Convert a be64 array to a host64 array */
INLINE void
be_to_host64(void *out, const void *in, size_t sz)
{
#if BYTE_ORDER == BIG_ENDIAN
	memcpy(out, in, sz);
#else
	be_to_le64(out, in, sz);
#endif
}

/** Convert a host64 array to a be64 array */
INLINE void
host_to_be64(void *out, const void *in, size_t sz)
{	be_to_host64(out, in, sz); }


#undef INLINE


#endif
