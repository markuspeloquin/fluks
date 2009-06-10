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
#	error "BYTE_ORDER not defined"
#endif
#ifndef BIG_ENDIAN
#	error "BIG_ENDIAN not defined"
#endif
#ifndef LITTLE_ENDIAN
#	error "LITTLE_ENDIAN not defined"
#endif

#ifdef __cplusplus
#	define INLINE inline
#else
#	define INLINE static inline
#endif

/** Convert a byte/be32 array to an le32 array */
INLINE void
be_to_le32(void *out, const void *in, size_t sz)
{
	register uint8_t	*o8 = (uint8_t *)out;
	register const uint8_t	*i8 = (const uint8_t *)in;
	for (size_t i = 0; i < sz; i++)
		o8[i] = i8[i ^ 3];
}

/** Convert an le32 array to a byte/be32 array */
INLINE void
le_to_be32(void *out, const void *in, size_t sz)
{	be_to_le32(out, in, sz); }

/** Convert a byte/be32 array to a host32 array */
INLINE void
be_to_host32(void *out, const void *in, size_t sz)
{
#if BYTE_ORDER == BIG_ENDIAN
	memcpy(out, in, sz);
#else
	be_to_le32(out, in, sz);
#endif
}

/** Convert a host32 array to a byte/be32 array */
INLINE void
host_to_be32(void *out, const void *in, size_t sz)
{	be_to_host32(out, in, sz); }

/** Convert a le32 array to a host32 array */
INLINE void
le_to_host32(void *out, const void *in, size_t sz)
{
#if BYTE_ORDER == BIG_ENDIAN
	be_to_le32(out, in, sz);
#else
	memcpy(out, in, sz);
#endif
}

/** Convert a host32 array to a le32 array */
INLINE void
host_to_le32(void *out, const void *in, size_t sz)
{	le_to_host32(out, in, sz); }

/** Convert an le64 array to a byte/be64 array */
INLINE void
be_to_le64(void *out, const void *in, size_t sz)
{
	register uint8_t	*o8 = (uint8_t *)out;
	register const uint8_t	*i8 = (const uint8_t *)in;
	for (size_t i = 0; i < sz; i++)
		o8[i] = i8[i ^ 7];
}

/** Convert a byte/be64 array to an le64 array */
INLINE void
le_to_be64(void *out, const void *in, size_t sz)
{	be_to_le64(out, in, sz); }

/** Convert a le64 array to a host64 array */
INLINE void
le_to_host64(void *out, const void *in, size_t sz)
{
#if BYTE_ORDER == BIG_ENDIAN
	be_to_le64(out, in, sz);
#else
	memcpy(out, in, sz);
#endif
}

/** Convert a host64 array to a le64 array */
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
