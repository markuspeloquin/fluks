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

static inline void
transform(const uint32_t x[BLK_WORDS], uint32_t y[BLK_WORDS])
{
	y[0] = ROL(x[0], 13);
	y[2] = ROL(x[2], 3);
	y[1] = x[1] ^ y[0] ^ y[2];
	y[3] = x[3] ^ y[2] ^ (y[0] << 3);
	y[1] = ROL(y[1], 1);
	y[3] = ROL(y[3], 7);
	y[0] = y[0] ^ y[1] ^ y[3];
	y[2] = y[2] ^ y[3] ^ (y[1] << 7);
	y[0] = ROL(y[0], 5);
	y[2] = ROL(y[2], 22);
}

static inline void
inv_transform(const uint32_t x[BLK_WORDS], uint32_t y[BLK_WORDS])
{
	y[2] = ROR(x[2], 22);
	y[0] = ROR(x[0], 5);
	y[2] = y[2] ^ x[3] ^ (x[1] << 7);
	y[0] = y[0] ^ x[1] ^ x[3];
	y[3] = ROR(x[3], 7);
	y[1] = ROR(x[1], 1);
	y[3] = y[3] ^ y[2] ^ (y[0] << 3);
	y[1] = y[1] ^ y[0] ^ y[2];
	y[2] = ROR(y[2], 3);
	y[0] = ROR(y[0], 13);
}

static inline void
keying(uint32_t x[BLK_WORDS], const uint32_t subkey[BLK_WORDS])
{
	x[0] ^= subkey[0];
	x[1] ^= subkey[1];
	x[2] ^= subkey[2];
	x[3] ^= subkey[3];
}

/* it appears these functions aren't needed somehow? it makes sense as
 * they don't increase security at all, but why are they then in the spec? */
#ifdef UNNEEDED
static void
perm_initial(uint32_t y[BLK_WORDS])
{
	/* copy the first bit off each word of 'a' and write to the first
	 * four bits of 'y'; copy second bits off each word of 'a' and write
	 * to the second set of four bits in 'y'; repeat; this is done
	 * in reverse below to make the assignment simpler; also,
	 * the loop works in 32-bit chunks */
	uint32_t x[BLK_WORDS];
	x[0] = y[0];
	x[1] = y[1];
	x[2] = y[2];
	x[3] = y[3];
	for (uint8_t i = 0; i < BLK_WORDS; i++) {
		y[3 - i] =
		    (x[0] & 0x80) << 24 |
		    (x[1] & 0x80) << 23 |
		    (x[2] & 0x80) << 22 |
		    (x[3] & 0x80) << 21 |

		    (x[0] & 0x40) << 21 |
		    (x[1] & 0x40) << 20 |
		    (x[2] & 0x40) << 19 |
		    (x[3] & 0x40) << 18 |

		    (x[0] & 0x20) << 18 |
		    (x[1] & 0x20) << 17 |
		    (x[2] & 0x20) << 16 |
		    (x[3] & 0x20) << 15 |

		    (x[0] & 0x10) << 15 |
		    (x[1] & 0x10) << 14 |
		    (x[2] & 0x10) << 13 |
		    (x[3] & 0x10) << 12 |

		    (x[0] & 0x08) << 12 |
		    (x[1] & 0x08) << 11 |
		    (x[2] & 0x08) << 10 |
		    (x[3] & 0x08) << 9  |

		    (x[0] & 0x04) << 9 |
		    (x[1] & 0x04) << 8 |
		    (x[2] & 0x04) << 7 |
		    (x[3] & 0x04) << 6 |

		    (x[0] & 0x02) << 6 |
		    (x[1] & 0x02) << 5 |
		    (x[2] & 0x02) << 4 |
		    (x[3] & 0x02) << 3 |

		    (x[0] & 0x01) << 3 |
		    (x[1] & 0x01) << 2 |
		    (x[2] & 0x01) << 1 |
		    (x[3] & 0x01);

		x[0] >>= 8;
		x[1] >>= 8;
		x[2] >>= 8;
		x[3] >>= 8;
	}
}

static void
perm_final(uint32_t y[BLK_WORDS])
{
	/* copy first bit off of each set of four bits in 'x' (in order) to
	 * first word of 'y'; copy second bit off into second word; etc.;
	 * done in reverse for slight increase in simplicity */
	uint32_t x[BLK_WORDS];
	x[0] = y[0];
	x[1] = y[1];
	x[2] = y[2];
	x[3] = y[3];
	for (uint8_t i = 0; i < BLK_WORDS; i++) {
		y[3 - i] =
		    (x[0] & 0x10000000) << 3  |
		    (x[0] & 0x01000000) << 6  |
		    (x[0] & 0x00100000) << 9  |
		    (x[0] & 0x00010000) << 12 |
		    (x[0] & 0x00001000) << 15 |
		    (x[0] & 0x00000100) << 18 |
		    (x[0] & 0x00000010) << 21 |
		    (x[0] & 0x00000001) << 24 |

		    /* left shift 8 less than last time */
		    (x[1] & 0x10000000) >> 5  |
		    (x[1] & 0x01000000) >> 2  |
		    (x[1] & 0x00100000) << 1  |
		    (x[1] & 0x00010000) << 4  |
		    (x[1] & 0x00001000) << 7  |
		    (x[1] & 0x00000100) << 10 |
		    (x[1] & 0x00000010) << 13 |
		    (x[1] & 0x00000001) << 16 |

		    (x[2] & 0x10000000) >> 13 |
		    (x[2] & 0x01000000) >> 10 |
		    (x[2] & 0x00100000) >> 7  |
		    (x[2] & 0x00010000) >> 4  |
		    (x[2] & 0x00001000) >> 1  |
		    (x[2] & 0x00000100) << 2  |
		    (x[2] & 0x00000010) << 5  |
		    (x[2] & 0x00000001) << 8  |

		    (x[3] & 0x10000000) >> 21 |
		    (x[3] & 0x01000000) >> 18 |
		    (x[3] & 0x00100000) >> 15 |
		    (x[3] & 0x00010000) >> 12 |
		    (x[3] & 0x00001000) >> 9  |
		    (x[3] & 0x00000100) >> 6  |
		    (x[3] & 0x00000010) >> 3  |
		    (x[3] & 0x00000001);

		x[0] >>= 1;
		x[1] >>= 1;
		x[2] >>= 1;
		x[3] >>= 1;
	}
}
#endif

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
	S3(w + 0x00, ctx->subkeys[ 0]);
	S2(w + 0x04, ctx->subkeys[ 1]);
	S1(w + 0x08, ctx->subkeys[ 2]);
	S0(w + 0x0c, ctx->subkeys[ 3]);
	S7(w + 0x10, ctx->subkeys[ 4]);
	S6(w + 0x14, ctx->subkeys[ 5]);
	S5(w + 0x18, ctx->subkeys[ 6]);
	S4(w + 0x1c, ctx->subkeys[ 7]);
	S3(w + 0x20, ctx->subkeys[ 8]);
	S2(w + 0x24, ctx->subkeys[ 9]);
	S1(w + 0x28, ctx->subkeys[10]);
	S0(w + 0x2c, ctx->subkeys[11]);
	S7(w + 0x30, ctx->subkeys[12]);
	S6(w + 0x34, ctx->subkeys[13]);
	S5(w + 0x38, ctx->subkeys[14]);
	S4(w + 0x3c, ctx->subkeys[15]);
	S3(w + 0x40, ctx->subkeys[16]);
	S2(w + 0x44, ctx->subkeys[17]);
	S1(w + 0x48, ctx->subkeys[18]);
	S0(w + 0x4c, ctx->subkeys[19]);
	S7(w + 0x50, ctx->subkeys[20]);
	S6(w + 0x54, ctx->subkeys[21]);
	S5(w + 0x58, ctx->subkeys[22]);
	S4(w + 0x5c, ctx->subkeys[23]);
	S3(w + 0x60, ctx->subkeys[24]);
	S2(w + 0x64, ctx->subkeys[25]);
	S1(w + 0x68, ctx->subkeys[26]);
	S0(w + 0x6c, ctx->subkeys[27]);
	S7(w + 0x70, ctx->subkeys[28]);
	S6(w + 0x74, ctx->subkeys[29]);
	S5(w + 0x78, ctx->subkeys[30]);
	S4(w + 0x7c, ctx->subkeys[31]);
	S3(w + 0x80, ctx->subkeys[32]);

	return 0;
}

void
serpent_encrypt(const struct serpent_ctx *ctx,
    const uint8_t input[SERPENT_BLOCK], uint8_t out[SERPENT_BLOCK])
{
	uint32_t	x[BLK_WORDS];
	uint32_t	y[BLK_WORDS];

	le_to_host32(x, input, SERPENT_BLOCK);

	/* Start to encrypt the plaintext x */
	keying(x, ctx->subkeys[ 0]);
	S0(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[ 1]);
	S1(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[ 2]);
	S2(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[ 3]);
	S3(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[ 4]);
	S4(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[ 5]);
	S5(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[ 6]);
	S6(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[ 7]);
	S7(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[ 8]);
	S0(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[ 9]);
	S1(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[10]);
	S2(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[11]);
	S3(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[12]);
	S4(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[13]);
	S5(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[14]);
	S6(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[15]);
	S7(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[16]);
	S0(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[17]);
	S1(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[18]);
	S2(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[19]);
	S3(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[20]);
	S4(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[21]);
	S5(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[22]);
	S6(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[23]);
	S7(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[24]);
	S0(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[25]);
	S1(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[26]);
	S2(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[27]);
	S3(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[28]);
	S4(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[29]);
	S5(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[30]);
	S6(x, y);
	transform(y, x);
	keying(x, ctx->subkeys[31]);
	S7(x, y);
	keying(y, ctx->subkeys[32]);
	/* The ciphertext is now in y */

	host_to_le32(out, y, SERPENT_BLOCK);
}

void
serpent_decrypt(const struct serpent_ctx *ctx,
    const uint8_t input[SERPENT_BLOCK], uint8_t out[SERPENT_BLOCK])
{
	uint32_t	x[BLK_WORDS];
	uint32_t	y[BLK_WORDS];

	le_to_host32(x, input, SERPENT_BLOCK);

	/* Start to decrypt the ciphertext x */
	keying(x, ctx->subkeys[32]);
	Sinv7(x, y);
	keying(y, ctx->subkeys[31]);
	inv_transform(y, x);
	Sinv6(x, y);
	keying(y, ctx->subkeys[30]);
	inv_transform(y, x);
	Sinv5(x, y);
	keying(y, ctx->subkeys[29]);
	inv_transform(y, x);
	Sinv4(x, y);
	keying(y, ctx->subkeys[28]);
	inv_transform(y, x);
	Sinv3(x, y);
	keying(y, ctx->subkeys[27]);
	inv_transform(y, x);
	Sinv2(x, y);
	keying(y, ctx->subkeys[26]);
	inv_transform(y, x);
	Sinv1(x, y);
	keying(y, ctx->subkeys[25]);
	inv_transform(y, x);
	Sinv0(x, y);
	keying(y, ctx->subkeys[24]);
	inv_transform(y, x);
	Sinv7(x, y);
	keying(y, ctx->subkeys[23]);
	inv_transform(y, x);
	Sinv6(x, y);
	keying(y, ctx->subkeys[22]);
	inv_transform(y, x);
	Sinv5(x, y);
	keying(y, ctx->subkeys[21]);
	inv_transform(y, x);
	Sinv4(x, y);
	keying(y, ctx->subkeys[20]);
	inv_transform(y, x);
	Sinv3(x, y);
	keying(y, ctx->subkeys[19]);
	inv_transform(y, x);
	Sinv2(x, y);
	keying(y, ctx->subkeys[18]);
	inv_transform(y, x);
	Sinv1(x, y);
	keying(y, ctx->subkeys[17]);
	inv_transform(y, x);
	Sinv0(x, y);
	keying(y, ctx->subkeys[16]);
	inv_transform(y, x);
	Sinv7(x, y);
	keying(y, ctx->subkeys[15]);
	inv_transform(y, x);
	Sinv6(x, y);
	keying(y, ctx->subkeys[14]);
	inv_transform(y, x);
	Sinv5(x, y);
	keying(y, ctx->subkeys[13]);
	inv_transform(y, x);
	Sinv4(x, y);
	keying(y, ctx->subkeys[12]);
	inv_transform(y, x);
	Sinv3(x, y);
	keying(y, ctx->subkeys[11]);
	inv_transform(y, x);
	Sinv2(x, y);
	keying(y, ctx->subkeys[10]);
	inv_transform(y, x);
	Sinv1(x, y);
	keying(y, ctx->subkeys[ 9]);
	inv_transform(y, x);
	Sinv0(x, y);
	keying(y, ctx->subkeys[ 8]);
	inv_transform(y, x);
	Sinv7(x, y);
	keying(y, ctx->subkeys[ 7]);
	inv_transform(y, x);
	Sinv6(x, y);
	keying(y, ctx->subkeys[ 6]);
	inv_transform(y, x);
	Sinv5(x, y);
	keying(y, ctx->subkeys[ 5]);
	inv_transform(y, x);
	Sinv4(x, y);
	keying(y, ctx->subkeys[ 4]);
	inv_transform(y, x);
	Sinv3(x, y);
	keying(y, ctx->subkeys[ 3]);
	inv_transform(y, x);
	Sinv2(x, y);
	keying(y, ctx->subkeys[ 2]);
	inv_transform(y, x);
	Sinv1(x, y);
	keying(y, ctx->subkeys[ 1]);
	inv_transform(y, x);
	Sinv0(x, y);
	keying(y, ctx->subkeys[ 0]);
	/* The plaintext is now in y */

	host_to_le32(out, y, SERPENT_BLOCK);
}
