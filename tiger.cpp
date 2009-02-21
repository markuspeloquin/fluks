#include <endian.h>
#include <stdint.h>

extern uint64_t table[4 * 256];

/* This is the official definition of round */
inline void
round(uint64_t &a, uint64_t &b, uint64_t &c, uint64_t x, uint8_t mul)
{
#define t1 table
#define t2 (table + 256)
#define t3 (table + 256 * 2)
#define t4 (table + 256 * 3)
	c ^= x;
	a -=
	    t1[(c >> 0 * 8) & 0xFF] ^
	    t2[(c >> 2 * 8) & 0xFF] ^
	    t3[(c >> 4 * 8) & 0xFF] ^
	    t4[(c >> 6 * 8) & 0xFF];
	b +=
	    t4[(c >> 1 * 8) & 0xFF] ^
	    t3[(c >> 3 * 8) & 0xFF] ^
	    t2[(c >> 5 * 8) & 0xFF] ^
	    t1[(c >> 7 * 8) & 0xFF];
	b *= mul;
#undef t1
#undef t2
#undef t3
#undef t4
}

inline void
tiger_compress(const uint64_t *str, int passes, uint64_t state[3])
{
	/* 'register' probably gets ignored by the compiler, but it's a
	 * hint from the original C89 macro-powered source */
	register uint64_t a, b, c, tmpa;
	uint64_t aa, bb, cc;
	register uint64_t x0, x1, x2, x3, x4, x5, x6, x7;
	int pass_no;

	a = state[0];
	b = state[1];
	c = state[2];

	x0 = str[0];
	x1 = str[1];
	x2 = str[2];
	x3 = str[3];
	x4 = str[4];
	x5 = str[5];
	x6 = str[6];
	x7 = str[7];

	/* begin old 'compress' macro */

	aa = a;
	bb = b;
	cc = c;

	for (pass_no = 0; pass_no < passes; pass_no++) {
		if (pass_no) {
			/* old macro 'key_schedule' */
			x0 -= x7 ^ 0xA5A5A5A5A5A5A5A5LL;
			x1 ^= x0;
			x2 += x1;
			x3 -= x2 ^ (~x1 << 19);
			x4 ^= x3;
			x5 += x4;
			x6 -= x5 ^ (~x4 >> 23);
			x7 ^= x6;
			x0 += x7;
			x1 -= x0 ^ (~x7 << 19);
			x2 ^= x1;
			x3 += x2;
			x4 -= x3 ^ (~x2 >> 23);
			x5 ^= x4;
			x6 += x5;
			x7 -= x6 ^ 0x0123456789ABCDEFLL;
		}

		/* old macro 'pass' */
		register uint8_t mul =
		    pass_no == 0 ? 5 :
		    pass_no == 1 ? 7 : 9;
		round(a, b, c, x0, mul);
		round(b, c, a, x1, mul);
		round(c, a, b, x2, mul);
		round(a, b, c, x3, mul);
		round(b, c, a, x4, mul);
		round(c, a, b, x5, mul);
		round(a, b, c, x6, mul);
		round(b, c, a, x7, mul);

		tmpa = a;
		a = c;
		c = b;
		b = tmpa;
	}

	/* feed forward */
	a ^= aa;
	b -= bb;
	c += cc;

	/* end old 'compress' macro */

	state[0] = a;
	state[1] = b;
	state[2] = c;
}

/* perhaps a greater genius can swap this out with a init(), update(), end()
 * implementation */
void
tiger_impl(const uint8_t *str, uint64_t length, int passes, uint64_t res[3])
{
	uint8_t			temp[64];
	register uint64_t	i;
	register uint64_t	j;
	register uint64_t	*buf = (uint64_t *)str;

	res[0] = 0x0123456789ABCDEFLL;
	res[1] = 0xFEDCBA9876543210LL;
	res[2] = 0xF096A5B4C3B2E187LL;

	for (i = length; i >= 64; i -= 64) {
#ifdef BIG_ENDIAN
		for (j = 0; j < 64; j++)
			temp[j ^ 7] = ((uint8_t *)buf)[j];
		tiger_compress((uint64_t *)temp, passes, res);
#else
		tiger_compress(buf, passes, res);
#endif
		buf += 8;
	}

#ifdef BIG_ENDIAN
	for (j = 0; j < i; j++)
		temp[j ^ 7] = ((uint8_t *)buf)[j];

	temp[j ^ 7] = 0x01;
	j++;
	for (; j & 7; j++)
		temp[j ^ 7] = 0;
#else
	for (j = 0; j < i; j++)
		temp[j] = ((uint8_t *)buf)[j];

	temp[j++] = 0x01;
	for (; j & 7; j++)
		temp[j] = 0;
#endif
	if(j > 56) {
		for (; j < 64; j++)
			temp[j] = 0;
		tiger_compress((uint64_t *)temp, res);
		j = 0;
	}

	for (; j < 56; j++)
		temp[j] = 0;
	((uint64_t *)(temp + 56))[0] = length << 3;
	tiger_compress((uint64_t *)temp, res);
}
