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

#include <stdint.h>

/* I'm halfway tempted to switch to C++ just so I can make these inline
 * functions that use pass-by-reference. */

/* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */
#define S0(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */
#define Sinv0(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */
#define S1(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */
#define Sinv1(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */
#define S2(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */
#define Sinv2(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */
#define S3(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */
#define Sinv3(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */
#define S4(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */
#define Sinv4(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */
#define S5(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */
#define Sinv5(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */
#define S6(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */
#define Sinv6(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */
#define S7(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)

/* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */
#define Sinv7(x0, x1, x2, x3, y0, y1, y2, y3)			do \
{								\
}								while(0)
