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

#include <stdint.h>

/* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */

/* depth = 5,7,4,2, Total gates=18 */
static inline void
S0(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t05, t06, t07, t08, t09,
	    t11, t12, t13, t14, t15, t17, t01;
	t01  = x[1] ^ x[2];
	t02  = x[0] | x[3];
	t03  = x[0] ^ x[1];
	y[3] = t02  ^ t01;
	t05  = x[2] | y[3];
	t06  = x[0] ^ x[3];
	t07  = x[1] | x[2];
	t08  = x[3] & t05;
	t09  = t03  & t07;
	y[2] = t09  ^ t08;
	t11  = t09  & y[2];
	t12  = x[2] ^ x[3];
	t13  = t07  ^ t11;
	t14  = x[1] & t06;
	t15  = t06  ^ t13;
	y[0] =      ~ t15;
	t17  = y[0] ^ t14;
	y[1] = t12  ^ t17;
}

/* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */

/* depth = 8,4,3,6, Total gates=19 */
static inline void
Sinv0(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t06, t08, t09,
	    t10, t12, t13, t14, t15, t17, t18, t01;
	t01  = x[2] ^ x[3];
	t02  = x[0] | x[1];
	t03  = x[1] | x[2];
	t04  = x[2] & t01;
	t05  = t02  ^ t01;
	t06  = x[0] | t04;
	y[2] =      ~ t05;
	t08  = x[1] ^ x[3];
	t09  = t03  & t08;
	t10  = x[3] | y[2];
	y[1] = t09  ^ t06;
	t12  = x[0] | t05;
	t13  = y[1] ^ t12;
	t14  = t03  ^ t10;
	t15  = x[0] ^ x[2];
	y[3] = t14  ^ t13;
	t17  = t05  & t13;
	t18  = t14  | t17;
	y[0] = t15  ^ t18;
}

/* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */

/* depth = 10,7,3,5, Total gates=18 */
static inline void
S1(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t06, t07, t08,
	    t10, t11, t12, t13, t16, t17, t01;
	t01  = x[0] | x[3];
	t02  = x[2] ^ x[3];
	t03  =      ~ x[1];
	t04  = x[0] ^ x[2];
	t05  = x[0] | t03;
	t06  = x[3] & t04;
	t07  = t01  & t02;
	t08  = x[1] | t06;
	y[2] = t02  ^ t05;
	t10  = t07  ^ t08;
	t11  = t01  ^ t10;
	t12  = y[2] ^ t11;
	t13  = x[1] & x[3];
	y[3] =      ~ t10;
	y[1] = t13  ^ t12;
	t16  = t10  | y[1];
	t17  = t05  & t16;
	y[0] = x[2] ^ t17;
}

/* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */

/* depth = 7,4,5,3, Total gates=18 */
static inline void
Sinv1(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t06, t07, t08,
	    t09, t10, t11, t14, t15, t17, t01;
	t01  = x[0] ^ x[1];
	t02  = x[1] | x[3];
	t03  = x[0] & x[2];
	t04  = x[2] ^ t02;
	t05  = x[0] | t04;
	t06  = t01  & t05;
	t07  = x[3] | t03;
	t08  = x[1] ^ t06;
	t09  = t07  ^ t06;
	t10  = t04  | t03;
	t11  = x[3] & t08;
	y[2] =      ~ t09;
	y[1] = t10  ^ t11;
	t14  = x[0] | y[2];
	t15  = t06  ^ y[1];
	y[3] = t01  ^ t04;
	t17  = x[2] ^ t15;
	y[0] = t14  ^ t17;
}

/* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */

/* depth = 3,8,11,7, Total gates=16 */
static inline void
S2(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t05, t06, t07, t08, t09,
	    t10, t12, t13, t14, t01;
	t01  = x[0] | x[2];
	t02  = x[0] ^ x[1];
	t03  = x[3] ^ t01;
	y[0] = t02  ^ t03;
	t05  = x[2] ^ y[0];
	t06  = x[1] ^ t05;
	t07  = x[1] | t05;
	t08  = t01  & t06;
	t09  = t03  ^ t07;
	t10  = t02  | t09;
	y[1] = t10  ^ t08;
	t12  = x[0] | x[3];
	t13  = t09  ^ y[1];
	t14  = x[1] ^ t13;
	y[3] =      ~ t09;
	y[2] = t12  ^ t14;
}

/* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */

/* depth = 3,6,8,3, Total gates=18 */
static inline void
Sinv2(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t06, t07, t08, t09,
	    t10, t11, t12, t15, t16, t17, t01;
	t01  = x[0] ^ x[3];
	t02  = x[2] ^ x[3];
	t03  = x[0] & x[2];
	t04  = x[1] | t02;
	y[0] = t01  ^ t04;
	t06  = x[0] | x[2];
	t07  = x[3] | y[0];
	t08  =      ~ x[3];
	t09  = x[1] & t06;
	t10  = t08  | t03;
	t11  = x[1] & t07;
	t12  = t06  & t02;
	y[3] = t09  ^ t10;
	y[1] = t12  ^ t11;
	t15  = x[2] & y[3];
	t16  = y[0] ^ y[1];
	t17  = t10  ^ t15;
	y[2] = t16  ^ t17;
}

/* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */

/* depth = 8,3,5,5, Total gates=18 */
static inline void
S3(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t06, t07, t08,
	    t09, t10, t11, t13, t14, t15, t01;
	t01  = x[0] ^ x[2];
	t02  = x[0] | x[3];
	t03  = x[0] & x[3];
	t04  = t01  & t02;
	t05  = x[1] | t03;
	t06  = x[0] & x[1];
	t07  = x[3] ^ t04;
	t08  = x[2] | t06;
	t09  = x[1] ^ t07;
	t10  = x[3] & t05;
	t11  = t02  ^ t10;
	y[3] = t08  ^ t09;
	t13  = x[3] | y[3];
	t14  = x[0] | t07;
	t15  = x[1] & t13;
	y[2] = t08  ^ t11;
	y[0] = t14  ^ t15;
	y[1] = t05  ^ t04;
}

/* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */

/* depth = 3,6,4,4, Total gates=17 */
static inline void
Sinv3(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t06, t07, t09,
	    t11, t12, t13, t14, t16, t01;
	t01  = x[2] | x[3];
	t02  = x[0] | x[3];
	t03  = x[2] ^ t02;
	t04  = x[1] ^ t02;
	t05  = x[0] ^ x[3];
	t06  = t04  & t03;
	t07  = x[1] & t01;
	y[2] = t05  ^ t06;
	t09  = x[0] ^ t03;
	y[0] = t07  ^ t03;
	t11  = y[0] | t05;
	t12  = t09  & t11;
	t13  = x[0] & y[2];
	t14  = t01  ^ t05;
	y[1] = x[1] ^ t12;
	t16  = x[1] | t13;
	y[3] = t14  ^ t16;
}

/* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */

/* depth = 6,7,5,3, Total gates=19 */
static inline void
S4(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t06, t08, t09,
	    t10, t11, t12, t13, t14, t15, t16, t01;
	t01  = x[0] | x[1];
	t02  = x[1] | x[2];
	t03  = x[0] ^ t02;
	t04  = x[1] ^ x[3];
	t05  = x[3] | t03;
	t06  = x[3] & t01;
	y[3] = t03  ^ t06;
	t08  = y[3] & t04;
	t09  = t04  & t05;
	t10  = x[2] ^ t06;
	t11  = x[1] & x[2];
	t12  = t04  ^ t08;
	t13  = t11  | t03;
	t14  = t10  ^ t09;
	t15  = x[0] & t05;
	t16  = t11  | t12;
	y[2] = t13  ^ t08;
	y[1] = t15  ^ t16;
	y[0] =      ~ t14;
}

/* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */

/* depth = 6,4,7,3, Total gates=17 */
static inline void
Sinv4(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t06, t07, t09,
	    t10, t11, t12, t13, t15, t01;
	t01  = x[1] | x[3];
	t02  = x[2] | x[3];
	t03  = x[0] & t01;
	t04  = x[1] ^ t02;
	t05  = x[2] ^ x[3];
	t06  =      ~ t03;
	t07  = x[0] & t04;
	y[1] = t05  ^ t07;
	t09  = y[1] | t06;
	t10  = x[0] ^ t07;
	t11  = t01  ^ t09;
	t12  = x[3] ^ t04;
	t13  = x[2] | t10;
	y[3] = t03  ^ t12;
	t15  = x[0] ^ t04;
	y[2] = t11  ^ t13;
	y[0] = t15  ^ t09;
}

/* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */

/* depth = 4,6,8,6, Total gates=17 */
static inline void
S5(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t07, t08, t09,
	    t10, t11, t12, t13, t14, t01;
	t01  = x[1] ^ x[3];
	t02  = x[1] | x[3];
	t03  = x[0] & t01;
	t04  = x[2] ^ t02;
	t05  = t03  ^ t04;
	y[0] =      ~ t05;
	t07  = x[0] ^ t01;
	t08  = x[3] | y[0];
	t09  = x[1] | t05;
	t10  = x[3] ^ t08;
	t11  = x[1] | t07;
	t12  = t03  | y[0];
	t13  = t07  | t10;
	t14  = t01  ^ t11;
	y[2] = t09  ^ t13;
	y[1] = t07  ^ t08;
	y[3] = t12  ^ t14;
}

/* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */

/* depth = 4,6,9,7, Total gates=17 */
static inline void
Sinv5(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t07, t08, t09,
	    t10, t12, t13, t15, t16, t01;
	t01  = x[0] & x[3];
	t02  = x[2] ^ t01;
	t03  = x[0] ^ x[3];
	t04  = x[1] & t02;
	t05  = x[0] & x[2];
	y[0] = t03  ^ t04;
	t07  = x[0] & y[0];
	t08  = t01  ^ y[0];
	t09  = x[1] | t05;
	t10  =      ~ x[1];
	y[1] = t08  ^ t09;
	t12  = t10  | t07;
	t13  = y[0] | y[1];
	y[3] = t02  ^ t12;
	t15  = t02  ^ t13;
	t16  = x[1] ^ x[3];
	y[2] = t16  ^ t15;
}

/* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */

/* depth = 8,3,6,3, Total gates=19 */
static inline void
S6(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t07, t08, t09,
	    t10, t11, t12, t13, t15, t17, t18, t01;
	t01  = x[0] & x[3];
	t02  = x[1] ^ x[2];
	t03  = x[0] ^ x[3];
	t04  = t01  ^ t02;
	t05  = x[1] | x[2];
	y[1] =      ~ t04;
	t07  = t03  & t05;
	t08  = x[1] & y[1];
	t09  = x[0] | x[2];
	t10  = t07  ^ t08;
	t11  = x[1] | x[3];
	t12  = x[2] ^ t11;
	t13  = t09  ^ t10;
	y[2] =      ~ t13;
	t15  = y[1] & t03;
	y[3] = t12  ^ t07;
	t17  = x[0] ^ x[1];
	t18  = y[2] ^ t15;
	y[0] = t17  ^ t18;
}

/* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */

/* depth = 5,3,8,6, Total gates=19 */
static inline void
Sinv6(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t06, t07, t08,
	    t09, t12, t13, t14, t15, t16, t17, t01;
	t01  = x[0] ^ x[2];
	t02  =      ~ x[2];
	t03  = x[1] & t01;
	t04  = x[1] | t02;
	t05  = x[3] | t03;
	t06  = x[1] ^ x[3];
	t07  = x[0] & t04;
	t08  = x[0] | t02;
	t09  = t07  ^ t05;
	y[1] = t06  ^ t08;
	y[0] =      ~ t09;
	t12  = x[1] & y[0];
	t13  = t01  & t05;
	t14  = t01  ^ t12;
	t15  = t07  ^ t13;
	t16  = x[3] | t02;
	t17  = x[0] ^ y[1];
	y[3] = t17  ^ t15;
	y[2] = t16  ^ t14;
}

/* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */

/* depth = 10,7,10,4, Total gates=19 */
static inline void
S7(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t05, t06, t08, t09,
	    t10, t11, t13, t14, t15, t16, t17, t01;
	t01  = x[0] & x[2];
	t02  =      ~ x[3];
	t03  = x[0] & t02;
	t04  = x[1] | t01;
	t05  = x[0] & x[1];
	t06  = x[2] ^ t04;
	y[3] = t03  ^ t06;
	t08  = x[2] | y[3];
	t09  = x[3] | t05;
	t10  = x[0] ^ t08;
	t11  = t04  & y[3];
	y[1] = t09  ^ t10;
	t13  = x[1] ^ y[1];
	t14  = t01  ^ y[1];
	t15  = x[2] ^ t05;
	t16  = t11  | t13;
	t17  = t02  | t14;
	y[0] = t15  ^ t17;
	y[2] = x[0] ^ t16;
}

/* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */

/* depth = 9,7,3,3, Total gates=18 */
static inline void
Sinv7(const uint32_t x[4], uint32_t y[4])
{
	register uint32_t t02, t03, t04, t06, t07, t08, t09,
	    t10, t11, t13, t14, t15, t16, t01;
	t01  = x[0] & x[1];
	t02  = x[0] | x[1];
	t03  = x[2] | t01;
	t04  = x[3] & t02;
	y[3] = t03  ^ t04;
	t06  = x[1] ^ t04;
	t07  = x[3] ^ y[3];
	t08  =      ~ t07;
	t09  = t06  | t08;
	t10  = x[1] ^ x[3];
	t11  = x[0] | x[3];
	y[1] = x[0] ^ t09;
	t13  = x[2] ^ t06;
	t14  = x[2] & t11;
	t15  = x[3] | y[1];
	t16  = t01  | t10;
	y[0] = t13  ^ t15;
	y[2] = t14  ^ t16;
}
