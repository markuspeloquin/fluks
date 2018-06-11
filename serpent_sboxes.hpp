/* Copyright (c) 2009-2010, Markus Peloquin <markus@cs.wisc.edu>
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

#ifndef SERPENT_SBOXES_HPP
#define SERPENT_SBOXES_HPP

#include <cstdint>

// Compared to the 'reference' implementation, there are 17% fewer gates!
// (242 vs 284)  Win!

// S0:    [3 8 f 1 a 6 5 b e d 4 2 7 0 9 c] in 14 gates (vs 19)
inline void
sbox_0(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
	t0 = x0 | x3;
	t1 = x1 ^ t0;
	y3 = x2 ^ t1;
	t2 = x0 ^ x3;
	t3 = x2 ^ t2;
	t4 = x1 & t2;
	t5 = x0 ^ t4;
	t6 = t3 & t5;
	y2 = t1 ^ t6;
	t7 = t3 ^ t5;
	t8 = y3 & t7;
	t9 = t3 ^ t8;
	y1 = ~t9;
	y0 = t7 ^ y1;
}

// Sinv0: [d 3 b 0 a 6 5 c 1 e 4 7 f 9 8 2] in 14 gates (vs 18)
inline void
sbox_0_inv(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
	t0 = x0 | x1;
	t1 = x2 ^ t0;
	t2 = ~t1;
	y2 = x3 ^ t2;
	t3 = x0 ^ x1;
	t4 = y2 ^ t3;
	t5 = x3 | t3;
	t6 = x0 ^ t5;
	t7 = t2 & t6;
	y0 = t4 ^ t7;
	t8 = t1 ^ y0;
	y3 = t6 ^ t8;
	t9 = y0 | y3;
	y1 = t2 ^ t9;
}

// S1:    [f c 2 7 9 0 5 a 1 b e 8 6 d 3 4] in 14 gates (vs 18)
inline void
sbox_1(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
	t0 = ~x1;
	t1 = x0 | t0;
	t2 = x2 ^ t1;
	y2 = x3 ^ t2;
	t3 = x0 ^ t0;
	t4 = y2 ^ t3;
	t5 = x3 | t3;
	t6 = x1 ^ t5;
	t7 = t2 & t6;
	y3 = t4 ^ t7;
	t8 = t2 ^ t6;
	y1 = y3 ^ t8;
	t9 = t4 & t8;
	y0 = t2 ^ t9;
}

// Sinv1: [5 8 2 e f 6 c 3 b 4 7 9 1 d a 0] in 15 gates (vs 18)
inline void
sbox_1_inv(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
	t0 = x1 & x3;
	t1 = x0 ^ t0;
	t2 = x3 ^ t1;
	y3 = x2 ^ t2;
	t3 = x1 ^ t1;
	t4 = x2 & t3;
	t5 = t1 ^ t4;
	t6 = y3 | t5;
	y1 = t3 ^ t6;
	t7 = ~y1;
	t8 = y3 | t7;
	y0 = t5 ^ t8;
	t9 = t7 | y0;
	y2 = t2 ^ t9;
}

// S2:    [8 6 7 9 3 c a f d 1 e 4 0 b 5 2] in 13 gates (vs 16)
inline void
sbox_2(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8;
	t0 = x0 & x2;
	t1 = x3 ^ t0;
	t2 = x1 ^ t1;
	y0 = x2 ^ t2;
	t3 = t1 & t2;
	t4 = x0 ^ t3;
	t5 = y0 ^ t4;
	y3 = ~t5;
	t6 = t1 & t4;
	t7 = x2 ^ t6;
	t8 = t5 | t7;
	y1 = t1 ^ t8;
	y2 = t7 ^ y1;
}

// Sinv2: [c 9 f 4 b e 1 2 0 3 6 d 5 8 a 7] in 14 gates (vs 18)
inline void
sbox_2_inv(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
	t0 = x0 ^ x3;
	t1 = x2 ^ x3;
	t2 = x1 | t1;
	y0 = t0 ^ t2;
	t3 = x1 ^ t1;
	t4 = x2 & t3;
	t5 = t2 ^ t4;
	t6 = t0 & t5;
	y1 = t3 ^ t6;
	t7 = x0 ^ y1;
	t8 = ~t5;
	y2 = t7 ^ t8;
	t9 = y0 & y2;
	y3 = t8 ^ t9;
}

// S3:    [0 f b 8 c 9 6 3 d 1 2 4 a 7 5 e] in 17 gates (vs 18)
inline void
sbox_3(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ta, tb, tc;
	t0 = x0 ^ x2;
	t1 = x3 ^ t0;
	t2 = x0 | t1;
	t3 = x2 ^ t2;
	t4 = x1 & t3;
	y2 = t1 ^ t4;
	t5 = x0 & x3;
	t6 = t0 & t3;
	t7 = x1 | t5;
	y1 = t6 ^ t7;
	t8 = x0 ^ x1;
	t9 = t1 ^ t6;
	ta = t4 | t8;
	y3 = t9 ^ ta;
	tb = x3 | ta;
	tc = t2 & tb;
	y0 = x1 ^ tc;
}

// Sinv3: [0 9 a 7 b e 6 d 3 5 c 2 4 8 f 1] in 16 gates (vs 17)
inline void
sbox_3_inv(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ta, tb;
	t0 = x1 ^ x2;
	t1 = x1 & t0;
	t2 = x0 ^ t1;
	t3 = x3 | t2;
	y0 = t0 ^ t3;
	t4 = x2 ^ x3;
	t5 = t2 ^ t4;
	t6 = t0 | t3;
	y2 = t5 ^ t6;
	t7 = x0 & t2;
	t8 = y0 | t5;
	y1 = t7 ^ t8;
	t9 = x1 ^ t8;
	ta = x3 & y0;
	tb = t2 | t9;
	y3 = ta ^ tb;
}

// S4:    [1 f 8 3 c 0 b 6 2 5 4 a 9 e 7 d] in 15 gates (vs 17)
inline void
sbox_4(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ta;
	t0 = x0 ^ x3;
	t1 = x3 & t0;
	t2 = x2 ^ t1;
	t3 = x1 | t2;
	y3 = t0 ^ t3;
	t4 = x1 & y3;
	t5 = t2 ^ t4;
	y0 = ~t5;
	t6 = x1 ^ t0;
	t7 = x3 ^ t2;
	t8 = t5 | t7;
	y2 = t6 ^ t8;
	t9 = x0 ^ t2;
	ta = t8 & y2;
	y1 = t9 ^ ta;
}

// Sinv4: [5 0 8 3 a 9 7 e 2 c b 6 4 f d 1] in 16 gates (vs 17)
inline void
sbox_4_inv(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ta, tb;
	t0 = x2 | x3;
	t1 = x1 ^ t0;
	t2 = x0 & t1;
	t3 = x2 ^ t2;
	y1 = x3 ^ t3;
	t4 = x1 | x3;
	t5 = x0 & t4;
	t6 = t1 ^ t5;
	y3 = x3 ^ t6;
	t7 = ~x0;
	t8 = y1 | t7;
	y0 = t6 ^ t8;
	t9 = x2 ^ t4;
	ta = t3 | t7;
	tb = t9 & ta;
	y2 = t8 ^ tb;
}

// S5:    [f 5 2 b 4 a 9 c 0 3 e 8 d 6 7 1] in 15 gates (vs 17)
inline void
sbox_5(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ta;
	t0 = x0 ^ x1;
	t1 = x1 & t0;
	t2 = x2 ^ t1;
	t3 = ~x3;
	t4 = t0 | t3;
	y0 = t2 ^ t4;
	t5 = t3 & y0;
	y1 = t0 ^ t5;
	t6 = x0 ^ t2;
	t7 = t0 ^ t3;
	t8 = y0 & t6;
	y2 = t7 ^ t8;
	t9 = x1 ^ t2;
	ta = t7 & y2;
	y3 = t9 ^ ta;
}

// Sinv5: [8 f 2 9 4 1 d e b 6 5 3 7 c a 0] in 16 gates (vs 17)
inline void
sbox_5_inv(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ta, tb;
	t0 = x0 & x3;
	t1 = x2 ^ t0;
	t2 = x1 & t1;
	t3 = x3 ^ t2;
	y0 = x0 ^ t3;
	t4 = x0 & y0;
	t5 = ~x1;
	t6 = t4 | t5;
	y3 = t1 ^ t6;
	t7 = x0 & y3;
	t8 = x1 ^ t7;
	y1 = t3 ^ t8;
	t9 = x1 ^ x3;
	ta = t1 ^ t9;
	tb = y0 | y1;
	y2 = ta ^ tb;
}

// S6:    [7 2 c 5 8 4 6 b e 9 1 f d 3 a 0] in 14 gates (vs 19)
inline void
sbox_6(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
	t0 = x0 & x3;
	t1 = x2 ^ t0;
	t2 = ~t1;
	y1 = x1 ^ t2;
	t3 = x0 ^ x3;
	t4 = x1 ^ t3;
	t5 = y1 | t3;
	t6 = x3 ^ t5;
	t7 = t2 & t6;
	y2 = t4 ^ t7;
	t8 = t2 ^ t6;
	y0 = y2 ^ t8;
	t9 = t4 & t8;
	y3 = t1 ^ t9;
}

// Sinv6: [f a 1 d 5 3 6 0 4 9 e 7 2 c 8 b] in 15 gates (vs 19)
inline void
sbox_6_inv(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ta;
	t0 = ~x2;
	t1 = x0 | t0;
	t2 = x3 ^ t1;
	y1 = x1 ^ t2;
	t3 = x0 ^ x2;
	t4 = t2 ^ t3;
	t5 = t3 & t4;
	t6 = x0 ^ t5;
	t7 = x1 & t6;
	y0 = t4 ^ t7;
	t8 = t6 ^ y0;
	y3 = x1 ^ t8;
	t9 = y0 & y3;
	ta = t2 ^ t9;
	y2 = ~ta;
}

// S7:    [1 d f 0 e 8 2 b 7 4 c a 9 3 5 6] in 17 gates (vs 18)
inline void
sbox_7(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ta, tb, tc;
	t0 = x1 ^ x2;
	t1 = x2 & t0;
	t2 = x3 ^ t1;
	t3 = x0 ^ t2;
	t4 = x0 & t3;
	y3 = t0 ^ t4;
	t5 = x1 ^ t3;
	t6 = t4 & y3;
	y1 = t5 ^ t6;
	t7 = y3 & t5;
	t8 = x3 & t2;
	y2 = t7 ^ t8;
	t9 = x1 ^ t7;
	ta = t2 | t9;
	tb = ~t3;
	tc = t0 | tb;
	y0 = ta ^ tc;
}

// Sinv7: [3 0 6 d 9 e f 8 5 c b 7 a 1 4 2] in 17 gates (vs 18)
inline void
sbox_7_inv(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ta, tb, tc;
	t0 = x0 & x1;
	t1 = x0 | x1;
	t2 = x3 & t1;
	t3 = x2 | t0;
	y3 = t2 ^ t3;
	t4 = x1 ^ t2;
	t5 = x3 ^ y3;
	t6 = ~t5;
	t7 = t4 | t6;
	y1 = x0 ^ t7;
	t8 = x3 | y1;
	t9 = x2 ^ t8;
	y0 = t4 ^ t9;
	ta = x1 ^ t7;
	tb = t9 ^ ta;
	tc = x0 | y3;
	y2 = tb ^ tc;
}

#endif
