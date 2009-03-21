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

/* I'm halfway tempted to switch to C++ just so I can make these inline
 * functions that use pass-by-reference. */

/* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */

/* depth = 5,7,4,2, Total gates=18 */
#define S0(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t05, t06, t07, t08, t09,	\
	    t11, t12, t13, t14, t15, t17, t01;			\
	t01 = x1  ^ x2;						\
	t02 = x0  | x3;						\
	t03 = x0  ^ x1;						\
	y3  = t02 ^ t01;					\
	t05 = x2  | y3;						\
	t06 = x0  ^ x3;						\
	t07 = x1  | x2;						\
	t08 = x3  & t05;					\
	t09 = t03 & t07;					\
	y2  = t09 ^ t08;					\
	t11 = t09 & y2;						\
	t12 = x2  ^ x3;						\
	t13 = t07 ^ t11;					\
	t14 = x1  & t06;					\
	t15 = t06 ^ t13;					\
	y0  =     ~ t15;					\
	t17 = y0  ^ t14;					\
	y1  = t12 ^ t17;					\
}								while(0)

/* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */

/* depth = 8,4,3,6, Total gates=19 */
#define Sinv0(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t06, t08, t09,	\
	    t10, t12, t13, t14, t15, t17, t18, t01;		\
	t01 = x2  ^ x3;						\
	t02 = x0  | x1;						\
	t03 = x1  | x2;						\
	t04 = x2  & t01;					\
	t05 = t02 ^ t01;					\
	t06 = x0  | t04;					\
	y2  =     ~ t05;					\
	t08 = x1  ^ x3;						\
	t09 = t03 & t08;					\
	t10 = x3  | y2;						\
	y1  = t09 ^ t06;					\
	t12 = x0  | t05;					\
	t13 = y1  ^ t12;					\
	t14 = t03 ^ t10;					\
	t15 = x0  ^ x2;						\
	y3  = t14 ^ t13;					\
	t17 = t05 & t13;					\
	t18 = t14 | t17;					\
	y0  = t15 ^ t18;					\
}								while(0)

/* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */

/* depth = 10,7,3,5, Total gates=18 */
#define S1(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t06, t07, t08,	\
	    t10, t11, t12, t13, t16, t17, t01;			\
	t01 = x0  | x3;						\
	t02 = x2  ^ x3;						\
	t03 =     ~ x1;						\
	t04 = x0  ^ x2;						\
	t05 = x0  | t03;					\
	t06 = x3  & t04;					\
	t07 = t01 & t02;					\
	t08 = x1  | t06;					\
	y2  = t02 ^ t05;					\
	t10 = t07 ^ t08;					\
	t11 = t01 ^ t10;					\
	t12 = y2  ^ t11;					\
	t13 = x1  & x3;						\
	y3  =     ~ t10;					\
	y1  = t13 ^ t12;					\
	t16 = t10 | y1;						\
	t17 = t05 & t16;					\
	y0  = x2  ^ t17;					\
}								while(0)

/* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */

/* depth = 7,4,5,3, Total gates=18 */
#define Sinv1(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t06, t07, t08,	\
	    t09, t10, t11, t14, t15, t17, t01;			\
	t01 = x0  ^ x1;						\
	t02 = x1  | x3;						\
	t03 = x0  & x2;						\
	t04 = x2  ^ t02;					\
	t05 = x0  | t04;					\
	t06 = t01 & t05;					\
	t07 = x3  | t03;					\
	t08 = x1  ^ t06;					\
	t09 = t07 ^ t06;					\
	t10 = t04 | t03;					\
	t11 = x3  & t08;					\
	y2  =     ~ t09;					\
	y1  = t10 ^ t11;					\
	t14 = x0  | y2;						\
	t15 = t06 ^ y1;						\
	y3  = t01 ^ t04;					\
	t17 = x2  ^ t15;					\
	y0  = t14 ^ t17;					\
}								while(0)

/* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */

/* depth = 3,8,11,7, Total gates=16 */
#define S2(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t05, t06, t07, t08, t09,	\
	    t10, t12, t13, t14, t01;				\
	t01 = x0  | x2;						\
	t02 = x0  ^ x1;						\
	t03 = x3  ^ t01;					\
	y0  = t02 ^ t03;					\
	t05 = x2  ^ y0;						\
	t06 = x1  ^ t05;					\
	t07 = x1  | t05;					\
	t08 = t01 & t06;					\
	t09 = t03 ^ t07;					\
	t10 = t02 | t09;					\
	y1  = t10 ^ t08;					\
	t12 = x0  | x3;						\
	t13 = t09 ^ y1;						\
	t14 = x1  ^ t13;					\
	y3  =     ~ t09;					\
	y2  = t12 ^ t14;					\
}								while(0)

/* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */

/* depth = 3,6,8,3, Total gates=18 */
#define Sinv2(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t06, t07, t08, t09,	\
	    t10, t11, t12, t15, t16, t17, t01;			\
	t01 = x0  ^ x3;						\
	t02 = x2  ^ x3;						\
	t03 = x0  & x2;						\
	t04 = x1  | t02;					\
	y0  = t01 ^ t04;					\
	t06 = x0  | x2;						\
	t07 = x3  | y0;						\
	t08 =     ~ x3;						\
	t09 = x1  & t06;					\
	t10 = t08 | t03;					\
	t11 = x1  & t07;					\
	t12 = t06 & t02;					\
	y3  = t09 ^ t10;					\
	y1  = t12 ^ t11;					\
	t15 = x2  & y3;						\
	t16 = y0  ^ y1;						\
	t17 = t10 ^ t15;					\
	y2  = t16 ^ t17;					\
}								while(0)

/* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */

/* depth = 8,3,5,5, Total gates=18 */
#define S3(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t06, t07, t08,	\
	    t09, t10, t11, t13, t14, t15, t01;			\
	t01 = x0  ^ x2;						\
	t02 = x0  | x3;						\
	t03 = x0  & x3;						\
	t04 = t01 & t02;					\
	t05 = x1  | t03;					\
	t06 = x0  & x1;						\
	t07 = x3  ^ t04;					\
	t08 = x2  | t06;					\
	t09 = x1  ^ t07;					\
	t10 = x3  & t05;					\
	t11 = t02 ^ t10;					\
	y3  = t08 ^ t09;					\
	t13 = x3  | y3;						\
	t14 = x0  | t07;					\
	t15 = x1  & t13;					\
	y2  = t08 ^ t11;					\
	y0  = t14 ^ t15;					\
	y1  = t05 ^ t04;					\
}								while(0)

/* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */

/* depth = 3,6,4,4, Total gates=17 */
#define Sinv3(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t06, t07, t09,	\
	    t11, t12, t13, t14, t16, t01;			\
	t01 = x2  | x3;						\
	t02 = x0  | x3;						\
	t03 = x2  ^ t02;					\
	t04 = x1  ^ t02;					\
	t05 = x0  ^ x3;						\
	t06 = t04 & t03;					\
	t07 = x1  & t01;					\
	y2  = t05 ^ t06;					\
	t09 = x0  ^ t03;					\
	y0  = t07 ^ t03;					\
	t11 = y0  | t05;					\
	t12 = t09 & t11;					\
	t13 = x0  & y2;						\
	t14 = t01 ^ t05;					\
	y1  = x1  ^ t12;					\
	t16 = x1  | t13;					\
	y3  = t14 ^ t16;					\
}								while(0)

/* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */

/* depth = 6,7,5,3, Total gates=19 */
#define S4(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t06, t08, t09,	\
	    t10, t11, t12, t13, t14, t15, t16, t01;		\
	t01 = x0  | x1;						\
	t02 = x1  | x2;						\
	t03 = x0  ^ t02;					\
	t04 = x1  ^ x3;						\
	t05 = x3  | t03;					\
	t06 = x3  & t01;					\
	y3  = t03 ^ t06;					\
	t08 = y3  & t04;					\
	t09 = t04 & t05;					\
	t10 = x2  ^ t06;					\
	t11 = x1  & x2;						\
	t12 = t04 ^ t08;					\
	t13 = t11 | t03;					\
	t14 = t10 ^ t09;					\
	t15 = x0  & t05;					\
	t16 = t11 | t12;					\
	y2  = t13 ^ t08;					\
	y1  = t15 ^ t16;					\
	y0  =     ~ t14;					\
}								while(0)

/* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */

/* depth = 6,4,7,3, Total gates=17 */
#define Sinv4(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t06, t07, t09,	\
	    t10, t11, t12, t13, t15, t01;			\
	t01 = x1  | x3;						\
	t02 = x2  | x3;						\
	t03 = x0  & t01;					\
	t04 = x1  ^ t02;					\
	t05 = x2  ^ x3;						\
	t06 =     ~ t03;					\
	t07 = x0  & t04;					\
	y1  = t05 ^ t07;					\
	t09 = y1  | t06;					\
	t10 = x0  ^ t07;					\
	t11 = t01 ^ t09;					\
	t12 = x3  ^ t04;					\
	t13 = x2  | t10;					\
	y3  = t03 ^ t12;					\
	t15 = x0  ^ t04;					\
	y2  = t11 ^ t13;					\
	y0  = t15 ^ t09;					\
}								while(0)

/* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */

/* depth = 4,6,8,6, Total gates=17 */
#define S5(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t07, t08, t09,	\
	    t10, t11, t12, t13, t14, t01;			\
	t01 = x1  ^ x3;						\
	t02 = x1  | x3;						\
	t03 = x0  & t01;					\
	t04 = x2  ^ t02;					\
	t05 = t03 ^ t04;					\
	y0  =     ~ t05;					\
	t07 = x0  ^ t01;					\
	t08 = x3  | y0;						\
	t09 = x1  | t05;					\
	t10 = x3  ^ t08;					\
	t11 = x1  | t07;					\
	t12 = t03 | y0;						\
	t13 = t07 | t10;					\
	t14 = t01 ^ t11;					\
	y2  = t09 ^ t13;					\
	y1  = t07 ^ t08;					\
	y3  = t12 ^ t14;					\
}								while(0)

/* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */

/* depth = 4,6,9,7, Total gates=17 */
#define Sinv5(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t07, t08, t09,	\
	    t10, t12, t13, t15, t16, t01;			\
	t01 = x0  & x3;						\
	t02 = x2  ^ t01;					\
	t03 = x0  ^ x3;						\
	t04 = x1  & t02;					\
	t05 = x0  & x2;						\
	y0  = t03 ^ t04;					\
	t07 = x0  & y0;						\
	t08 = t01 ^ y0;						\
	t09 = x1  | t05;					\
	t10 =     ~ x1;						\
	y1  = t08 ^ t09;					\
	t12 = t10 | t07;					\
	t13 = y0  | y1;						\
	y3  = t02 ^ t12;					\
	t15 = t02 ^ t13;					\
	t16 = x1  ^ x3;						\
	y2  = t16 ^ t15;					\
}								while(0)

/* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */

/* depth = 8,3,6,3, Total gates=19 */
#define S6(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t07, t08, t09,	\
	    t10, t11, t12, t13, t15, t17, t18, t01;		\
	t01 = x0  & x3;						\
	t02 = x1  ^ x2;						\
	t03 = x0  ^ x3;						\
	t04 = t01 ^ t02;					\
	t05 = x1  | x2;						\
	y1  =     ~ t04;					\
	t07 = t03 & t05;					\
	t08 = x1  & y1;						\
	t09 = x0  | x2;						\
	t10 = t07 ^ t08;					\
	t11 = x1  | x3;						\
	t12 = x2  ^ t11;					\
	t13 = t09 ^ t10;					\
	y2  =     ~ t13;					\
	t15 = y1  & t03;					\
	y3  = t12 ^ t07;					\
	t17 = x0  ^ x1;						\
	t18 = y2  ^ t15;					\
	y0  = t17 ^ t18;					\
}								while(0)

/* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */

/* depth = 5,3,8,6, Total gates=19 */
#define Sinv6(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t06, t07, t08,	\
	    t09, t12, t13, t14, t15, t16, t17, t01;		\
	t01 = x0  ^ x2;						\
	t02 =     ~ x2;						\
	t03 = x1  & t01;					\
	t04 = x1  | t02;					\
	t05 = x3  | t03;					\
	t06 = x1  ^ x3;						\
	t07 = x0  & t04;					\
	t08 = x0  | t02;					\
	t09 = t07 ^ t05;					\
	y1  = t06 ^ t08;					\
	y0  =     ~ t09;					\
	t12 = x1  & y0;						\
	t13 = t01 & t05;					\
	t14 = t01 ^ t12;					\
	t15 = t07 ^ t13;					\
	t16 = x3  | t02;					\
	t17 = x0  ^ y1;						\
	y3  = t17 ^ t15;					\
	y2  = t16 ^ t14;					\
}								while(0)

/* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */

/* depth = 10,7,10,4, Total gates=19 */
#define S7(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t05, t06, t08, t09,	\
	    t10, t11, t13, t14, t15, t16, t17, t01;		\
	t01 = x0  & x2;						\
	t02 =     ~ x3;						\
	t03 = x0  & t02;					\
	t04 = x1  | t01;					\
	t05 = x0  & x1;						\
	t06 = x2  ^ t04;					\
	y3  = t03 ^ t06;					\
	t08 = x2  | y3;						\
	t09 = x3  | t05;					\
	t10 = x0  ^ t08;					\
	t11 = t04 & y3;						\
	y1  = t09 ^ t10;					\
	t13 = x1  ^ y1;						\
	t14 = t01 ^ y1;						\
	t15 = x2  ^ t05;					\
	t16 = t11 | t13;					\
	t17 = t02 | t14;					\
	y0  = t15 ^ t17;					\
	y2  = x0  ^ t16;					\
}								while(0)

/* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */

/* depth = 9,7,3,3, Total gates=18 */
#define Sinv7(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
	register uint32_t t02, t03, t04, t06, t07, t08, t09,	\
	    t10, t11, t13, t14, t15, t16, t01;			\
	t01 = x0  & x1;						\
	t02 = x0  | x1;						\
	t03 = x2  | t01;					\
	t04 = x3  & t02;					\
	y3  = t03 ^ t04;					\
	t06 = x1  ^ t04;					\
	t07 = x3  ^ y3;						\
	t08 =     ~ t07;					\
	t09 = t06 | t08;					\
	t10 = x1  ^ x3;						\
	t11 = x0  | x3;						\
	y1  = x0  ^ t09;					\
	t13 = x2  ^ t06;					\
	t14 = x2  & t11;					\
	t15 = x3  | y1;						\
	t16 = t01 | t10;					\
	y0  = t13 ^ t15;					\
	y2  = t14 ^ t16;					\
}								while(0)
