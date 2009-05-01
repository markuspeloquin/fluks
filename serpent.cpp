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

#include <cassert>

#include "crypto_ops.h"
#include "endian.h"
#include "serpent.h"
#include "serpent_sboxes.hpp"

// PHI: Constant used in the key schedule
const uint32_t PHI = 0x9e3779b9UL;
const size_t KEY_BYTES = 32;
const size_t BLK_WORDS = 4;

inline void
transform(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	y0 = ROL(x0, 13);
	y2 = ROL(x2, 3);
	y1 = x1 ^ y0 ^ y2;
	y3 = x3 ^ y2 ^ (y0 << 3);
	y1 = ROL(y1, 1);
	y3 = ROL(y3, 7);
	y0 ^= y1 ^ y3;
	y2 ^= y3 ^ (y1 << 7);
	y0 = ROL(y0, 5);
	y2 = ROL(y2, 22);
}

inline void
transform_inv(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	y2 = ROR(x2, 22);
	y0 = ROR(x0, 5);
	y2 ^= x3 ^ (x1 << 7);
	y0 ^= x1 ^ x3;
	y3 = ROR(x3, 7);
	y1 = ROR(x1, 1);
	y3 ^= y2 ^ (y0 << 3);
	y1 ^= y0 ^ y2;
	y2 = ROR(y2, 3);
	y0 = ROR(y0, 13);
}

inline void
keying(uint32_t &x0, uint32_t &x1, uint32_t &x2, uint32_t &x3,
    const uint32_t subkey[4])
{
	x0 ^= subkey[0];
	x1 ^= subkey[1];
	x2 ^= subkey[2];
	x3 ^= subkey[3];
}

extern "C" enum serpent_return
serpent_init(struct serpent_ctx *ctx, const uint8_t *keyin, size_t sz)
{
	// w starts at offset 8, allowing w to have some negative indices
	uint32_t	v[8 + 4 * 33];
	uint32_t	*w = v + 8;
	uint8_t		*v8 = reinterpret_cast<uint8_t *>(v);
	int16_t		i; // [-32,132]

	if(sz != 16 && sz != 24 && sz != 32)
		return SERPENT_BAD_KEY_MAT;

	// internal representation is little-endian
	le_to_host32(v8, keyin, sz);
	if (sz < 32) {
		// fill the remainder with the binary pattern b10000..., but
		// reversed
		v8[sz] = 0x1;
		for (i = sz + 1; i < 32; i++) v8[i] = 0;
	}

	// get w_0 through w_131 (4*33 values)
	for (i = 0; i < 132; i++)
		w[i] = ROL(w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ PHI ^ i, 11);

	// calculate round k_{4i..4i+3}=subkey[i] from w_{4i..4i+3}
	uint32_t *s = w;		// source
	uint32_t *d = ctx->subkeys[0];	// destination

	/* because of the way 2D arrays work in C (i.e. they aren't
	 * arrays of arrays, but a continuous sequence of arrays),
	 * it's fine to increment d by 4 each time */
	sbox_3(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_2(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_1(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_0(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;

	sbox_7(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_6(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_5(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_4(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_3(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_2(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_1(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_0(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;

	sbox_7(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_6(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_5(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_4(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_3(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_2(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_1(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_0(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;

	sbox_7(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_6(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_5(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_4(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_3(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_2(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_1(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_0(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;

	sbox_7(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_6(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_5(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_4(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]); s+=4; d+=4;
	sbox_3(s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]);

	return SERPENT_OKAY;
}

extern "C" void
serpent_encrypt(const struct serpent_ctx *ctx,
    const uint8_t in[SERPENT_BLOCK], uint8_t out[SERPENT_BLOCK])
{
	uint32_t		buf[SERPENT_BLOCK/4];
	register uint32_t	x0, x1, x2, x3;
	register uint32_t	y0, y1, y2, y3;

	// fix both endian and alignment
	le_to_host32(buf, in, SERPENT_BLOCK);
	x0 = buf[0];
	x1 = buf[1];
	x2 = buf[2];
	x3 = buf[3];

	// x = b0 = plaintext
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 0]);
	sbox_0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	// x = b1
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 1]);
	sbox_1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	// x = b2
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 2]);
	sbox_2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[ 3]);
	sbox_3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[ 4]);
	sbox_4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[ 5]);
	sbox_5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[ 6]);
	sbox_6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[ 7]);
	sbox_7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[ 8]);
	sbox_0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[ 9]);
	sbox_1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[10]);
	sbox_2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[11]);
	sbox_3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[12]);
	sbox_4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[13]);
	sbox_5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[14]);
	sbox_6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[15]);
	sbox_7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[16]);
	sbox_0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[17]);
	sbox_1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[18]);
	sbox_2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[19]);
	sbox_3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[20]);
	sbox_4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[21]);
	sbox_5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[22]);
	sbox_6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[23]);
	sbox_7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[24]);
	sbox_0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[25]);
	sbox_1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[26]);
	sbox_2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[27]);
	sbox_3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[28]);
	sbox_4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[29]);
	sbox_5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);

	keying(		x0,x1,x2,x3,	ctx->subkeys[30]);
	sbox_6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	// x = b31
	keying(		x0,x1,x2,x3,	ctx->subkeys[31]);
	sbox_7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[32]);
	// y = b32 = ciphertext

	buf[0] = y0;
	buf[1] = y1;
	buf[2] = y2;
	buf[3] = y3;
	host_to_le32(out, buf, SERPENT_BLOCK);
}

extern "C" void
serpent_decrypt(const struct serpent_ctx *ctx,
    const uint8_t in[SERPENT_BLOCK], uint8_t out[SERPENT_BLOCK])
{
	uint32_t		buf[SERPENT_BLOCK/4];
	register uint32_t	x0, x1, x2, x3;
	register uint32_t	y0, y1, y2, y3;

	// fix both endian and alignment
	le_to_host32(buf, in, SERPENT_BLOCK);
	x0 = buf[0];
	x1 = buf[1];
	x2 = buf[2];
	x3 = buf[3];

	// x = b32 = ciphertext
	keying(		x0,x1,x2,x3,	ctx->subkeys[32]);
	sbox_7_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[31]);
	// y = b31
	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_6_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[30]);
	// y = b30
	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_5_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[29]);
	// y = b29
	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_4_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[28]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_3_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[27]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_2_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[26]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_1_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[25]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_0_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[24]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_7_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[23]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_6_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[22]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_5_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[21]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_4_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[20]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_3_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[19]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_2_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[18]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_1_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[17]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_0_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[16]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_7_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[15]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_6_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[14]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_5_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[13]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_4_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[12]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_3_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[11]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_2_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[10]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_1_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 9]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_0_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 8]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_7_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 7]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_6_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 6]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_5_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 5]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_4_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 4]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_3_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 3]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_2_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 2]);

	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_1_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 1]);
	// y = b1
	transform_inv(	y0,y1,y2,y3,	x0,x1,x2,x3);
	sbox_0_inv(	x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 0]);
	// y = b0 = plaintext

	buf[0] = y0;
	buf[1] = y1;
	buf[2] = y2;
	buf[3] = y3;
	host_to_le32(out, buf, SERPENT_BLOCK);
}
