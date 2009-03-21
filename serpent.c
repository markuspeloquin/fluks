/* Copyright (C) 1998 Ross Anderson, Eli Biham, Lars Knudsen
 * All rights reserved.
 *
 * This code is freely distributed for AES selection process.
 * No other use is allowed.
 * 
 * Copyright remains of the copyright holders, and as such any Copyright
 * notices in the code are not to be removed.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only for the AES selection process, provided
 * that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed without the authors permission.
 *  i.e. this code cannot simply be copied and put under another distribution
 * licence [including the GNU Public Licence.]
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "crypto_ops.h"
#include "endian.h"
#include "serpent.h"
#include "serpentsboxes.h"

/* PHI: Constant used in the key schedule */
const uint32_t PHI = 0x9e3779b9UL;
const size_t KEY_BYTES = 32;
const size_t BLK_WORDS = 4;

/* it would be really nice if these could be C++ pass-by-reference inline
 * functions */

#define transform(x0, x1, x2, x3, y0, y1, y2, y3)		do \
{								\
	y0 = ROL(x0, 13);					\
	y2 = ROL(x2, 3);					\
	y1 = x1 ^ y0 ^ y2;					\
	y3 = x3 ^ y2 ^ (y0 << 3);				\
	y1 = ROL(y1, 1);					\
	y3 = ROL(y3, 7);					\
	y0 = y0 ^ y1 ^ y3;					\
	y2 = y2 ^ y3 ^ (y1 << 7);				\
	y0 = ROL(y0, 5);					\
	y2 = ROL(y2, 22);					\
}								while(0)

#define inv_transform(x0, x1, x2, x3, y0, y1, y2, y3)		do \
{								\
	y2 = ROR(x2, 22);					\
	y0 = ROR(x0, 5);					\
	y2 = y2 ^ x3 ^ (x1 << 7);				\
	y0 = y0 ^ x1 ^ x3;					\
	y3 = ROR(x3, 7);					\
	y1 = ROR(x1, 1);					\
	y3 = y3 ^ y2 ^ (y0 << 3);				\
	y1 = y1 ^ y0 ^ y2;					\
	y2 = ROR(y2, 3);					\
	y0 = ROR(y0, 13);					\
}								while(0)

#define keying(x0, x1, x2, x3, subkey)				do \
{								\
	x0 ^= subkey[0];					\
	x1 ^= subkey[1];					\
	x2 ^= subkey[2];					\
	x3 ^= subkey[3];					\
}								while(0)

enum serpent_return
serpent_init(struct serpent_ctx *ctx, const uint8_t *keyin, size_t sz)
{
	uint32_t	w[132];
	uint8_t		i; /* [0,132] */

	uint8_t		*w8 = (uint8_t *)w;

	if(sz != 16 && sz != 24 && sz != 32)
		return SERPENT_BAD_KEY_MAT;

	le_to_host32(w8, keyin, sz);
	if (sz < 32) {
		/* the spec seems to indicate that the pattern used to
		 * fill the rest of the space is (binary) b1000..., though
		 * Crypt::Serpent, libgcrypt's implementation, and the
		 * standard Java implementation all write 0x1000... */
		w8[sz] = 0x1;
		for (i = sz + 1; i < 32; i++) w8[i] = 0;
	}

	/* get w_0 through w_7, write at positions 8 through 15 */
	for (i = 8; i < 16; i++)
		w[i] = ROL(w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ PHI ^ (i-8),
		    11);

	/* shift positions 8 through 15 to positions 0 through 7 */
	memcpy(w, w + 8, 32);

	/* get w_8 through w_131 */
	for (i = 8; i < 132; i++)
		w[i] = ROL(w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ PHI ^ i, 11);

	/* calculate round k_{4i..4i+3}=subkey[i] from w_{4i..4i+3} */
	uint32_t *s = w;		/* source */
	uint32_t *d = ctx->subkeys[0];	/* destination */
	for (i = 0; i < 33; i++) {
		switch (i & 7) {
		case 0:
			S3(	s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]);
			break;
		case 1:
			S2(	s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]);
			break;
		case 2:
			S1(	s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]);
			break;
		case 3:
			S0(	s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]);
			break;
		case 4:
			S7(	s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]);
			break;
		case 5:
			S6(	s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]);
			break;
		case 6:
			S5(	s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]);
			break;
		case 7:
			S4(	s[0],s[1],s[2],s[3],	d[0],d[1],d[2],d[3]);
		}
		s += 4;
		/* because of the way 2D arrays work in C (i.e. they aren't
		 * arrays of arrays, but a continuous sequence of arrays),
		 * this is fine */
		d += 4;
	}

	return 0;
}

void
serpent_encrypt(const struct serpent_ctx *ctx,
    const uint8_t input[SERPENT_BLOCK], uint8_t out[SERPENT_BLOCK])
{
	uint32_t		buf[SERPENT_BLOCK/4];
	register uint32_t	x0, x1, x2, x3;
	register uint32_t	y0, y1, y2, y3;

	/* fix both endian and alignment */
	le_to_host32(buf, input, SERPENT_BLOCK);
	x0 = buf[0];
	x1 = buf[1];
	x2 = buf[2];
	x3 = buf[3];

	/* Start to encrypt the plaintext x */
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 0]);
	S0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 1]);
	S1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 2]);
	S2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 3]);
	S3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 4]);
	S4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 5]);
	S5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 6]);
	S6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 7]);
	S7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 8]);
	S0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[ 9]);
	S1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[10]);
	S2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[11]);
	S3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[12]);
	S4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[13]);
	S5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[14]);
	S6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[15]);
	S7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[16]);
	S0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[17]);
	S1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[18]);
	S2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[19]);
	S3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[20]);
	S4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[21]);
	S5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[22]);
	S6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[23]);
	S7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[24]);
	S0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[25]);
	S1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[26]);
	S2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[27]);
	S3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[28]);
	S4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[29]);
	S5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[30]);
	S6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	keying(		x0,x1,x2,x3,	ctx->subkeys[31]);
	S7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[32]);
	/* The ciphertext is now in y */

	buf[0] = y0;
	buf[1] = y1;
	buf[2] = y2;
	buf[3] = y3;
	host_to_le32(out, buf, SERPENT_BLOCK);
}

void
serpent_decrypt(const struct serpent_ctx *ctx,
    const uint8_t input[SERPENT_BLOCK], uint8_t out[SERPENT_BLOCK])
{
	uint32_t		buf[SERPENT_BLOCK/4];
	register uint32_t	x0, x1, x2, x3;
	register uint32_t	y0, y1, y2, y3;

	/* fix both endian and alignment */
	le_to_host32(buf, input, SERPENT_BLOCK);
	x0 = buf[0];
	x1 = buf[1];
	x2 = buf[2];
	x3 = buf[3];

	/* Start to decrypt the ciphertext x */
	keying(		x0,x1,x2,x3,	ctx->subkeys[32]);
	Sinv7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[31]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[30]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[29]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[28]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[27]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[26]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[25]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[24]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[23]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[22]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[21]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[20]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[19]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[18]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[17]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[16]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[15]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[14]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[13]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[12]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[11]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[10]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 9]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 8]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv7(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 7]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv6(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 6]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv5(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 5]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv4(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 4]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv3(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 3]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv2(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 2]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv1(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 1]);
	inv_transform(	y0,y1,y2,y3,	x0,x1,x2,x3);
	Sinv0(		x0,x1,x2,x3,	y0,y1,y2,y3);
	keying(		y0,y1,y2,y3,	ctx->subkeys[ 0]);
	/* The plaintext is now in y */

	buf[0] = y0;
	buf[1] = y1;
	buf[2] = y2;
	buf[3] = y3;
	host_to_le32(out, buf, SERPENT_BLOCK);
}
