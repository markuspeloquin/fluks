/***************************************************************************
	PLATFORM.H	-- Platform-specific defines for TWOFISH code

	Submitters:
		Bruce Schneier, Counterpane Systems
		Doug Whiting,	Hi/fn
		John Kelsey,	Counterpane Systems
		Chris Hall,		Counterpane Systems
		David Wagner,	UC Berkeley
			
	Code Author:		Doug Whiting,	Hi/fn
		
	Version  1.00		April 1998
		
	Copyright 1998, Hi/fn and Counterpane Systems.  All rights reserved.
		
	Notes:
		*	Tab size is set to 4 characters in this file

***************************************************************************/

#ifndef PLATFORM_H
#define PLATFORM_H

#include <endian.h>
#include <stdint.h>

/* use intrinsic rotate if possible */
static inline uint32_t ROL(uint32_t x, uint8_t n)
{
	n &= 0x1f;
	return x << n | x >> (0x20 - n);
}

/* use intrinsic rotate if possible */
static inline uint32_t ROR(uint32_t x, uint8_t n)
{
	n &= 0x1f;
	return x >> n | x << (0x20 - n);
}

#if BYTE_ORDER == LITTLE_ENDIAN
#	define LittleEndian 1
#else
#	define LittleEndian 0
#endif

/* assume alignment is required */
#define ALIGN32 1

/* machine endian <-> little endian */
static inline uint32_t Bswap(uint32_t x)
{
#if BYTE_ORDER == BIG_ENDIAN
	return
	    (x & 0x000000ff) << 24 |
	    (x & 0x0000ff00) << 8 |
	    (x & 0x00ff0000) >> 8 |
	    (x & 0xff000000) >> 24;
#else
	return x;
#endif
}

#if BYTE_ORDER == LITTLE_ENDIAN
#	define	ADDR_XOR	0	/* NOP for little-endian machines */
#else
#	define	ADDR_XOR	3	/* convert byte address in dword */
#endif

/* extract byte N from x; N=0 corresponds to least significant */
static inline uint8_t _b(uint32_t x, uint8_t N)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return ((uint8_t *)&x)[N & 3];
#else
	return ((uint8_t *)&x)[N & 3 ^ 3];
#endif
}

/* 32-bit byte extraction (0=least significant) */
#define		b0(x)	_b(x,0)
#define		b1(x)	_b(x,1)
#define		b2(x)	_b(x,2)
#define		b3(x)	_b(x,3)

#endif
