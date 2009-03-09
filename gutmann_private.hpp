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

#include <boost/scoped_array.hpp>

#include <openssl/rand.h>

namespace fluks {
namespace {

// I repeated each so that the length of the string is a multiple of four
const uint8_t NUM_PATTERNS = 27;
const uint8_t PATTERN_LENGTH = 12;
const char PATTERNS[NUM_PATTERNS][PATTERN_LENGTH + 1] = {
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55",
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
    "\x92\x49\x24\x92\x49\x24\x92\x49\x24",
    "\x49\x24\x92\x49\x24\x92\x49\x24\x92",
    "\x24\x92\x49\x24\x92\x49\x24\x92\x49",
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "\x11\x11\x11\x11\x11\x11\x11\x11\x11",
    "\x22\x22\x22\x22\x22\x22\x22\x22\x22",
    "\x33\x33\x33\x33\x33\x33\x33\x33\x33",
    "\x44\x44\x44\x44\x44\x44\x44\x44\x44",
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55",
    "\x66\x66\x66\x66\x66\x66\x66\x66\x66",
    "\x77\x77\x77\x77\x77\x77\x77\x77\x77",
    "\x88\x88\x88\x88\x88\x88\x88\x88\x88",
    "\x99\x99\x99\x99\x99\x99\x99\x99\x99",
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb",
    "\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc",
    "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
    "\xee\xee\xee\xee\xee\xee\xee\xee\xee",
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    "\x92\x49\x24\x92\x49\x24\x92\x49\x24",
    "\x49\x24\x92\x49\x24\x92\x49\x24\x92",
    "\x24\x92\x49\x24\x92\x49\x24\x92\x49",
    "\x6d\xb6\xdb\x6d\xb6\xdb\x6d\xb6\xdb",
    "\xb6\xdb\x6d\xb6\xdb\x6d\xb6\xdb\x6d",
    "\xdb\x6d\xb6\xdb\x6d\xb6\xdb\x6d\xb6",
};

uint8_t rand_index(uint8_t max)
{
	// to give all numbers on [0,max) the same probability, disqualify
	// numbers as large as max_accept (e.g. if max is 25, max_accept
	// is 250; if there are 250 possible values, they can be divided
	// evenly into 25 groups)
	uint8_t max_accept = 256 / max * max;
	uint8_t r;
	do {
		if (!RAND_bytes(&r, 1))
			throw Ssl_error();
	} while (r < max_accept);
	return r % max;
}

template <class Fstream>
void write_pattern(Fstream &file, off_t pos,
    const char *buf, size_t bytes)
    throw (Disk_error)
{
	if (!file.seekp(pos, std::ios_base::beg))
		throw Disk_error("Gutmann erase: seek failed");

	if (!file.write(buf, bytes))
		throw Disk_error("Gutmann erase: write failed");

	file.flush();
}

} // end anon namespace
}

// TODO write rant about why the Gutmann erase method is stupid

template <class Fstream>
Fstream &
fluks::gutmann_erase(Fstream &file, off_t pos, size_t bytes)
    throw (Disk_error)
{
	char buf[bytes];
	uint8_t order[NUM_PATTERNS];

	// make order sequential
	for (uint8_t i = 0; i < NUM_PATTERNS; i++)
		order[i] = i;
	// randomize order
	for (uint8_t i = 0; i < NUM_PATTERNS; i++) {
		// swap value at order[i] with order[r], where r is random
		// in [i:NUM_PATTERNS)
		uint8_t r = i + rand_index(NUM_PATTERNS - i);
		uint8_t t = order[i];
		order[i] = order[r];
		order[r] = t;
	}

	for (uint8_t i = 0; i < 4; i++) {
		if (!RAND_bytes(reinterpret_cast<uint8_t *>(buf), bytes))
			throw Ssl_error();
		write_pattern(file, pos, buf, bytes);
	}
	for (uint8_t i = 0; i < NUM_PATTERNS; i++) {
		size_t j = 0;
		size_t blocks = bytes / PATTERN_LENGTH;
		uint8_t left = bytes % PATTERN_LENGTH;
		while (blocks--) {
			std::copy(PATTERNS[order[i]],
			    PATTERNS[order[i]] + PATTERN_LENGTH, buf + j);
			j += PATTERN_LENGTH;
		}
		if (left) {
			std::copy(PATTERNS[order[i]],
			    PATTERNS[order[i]] + left, buf + j);
		}
		write_pattern(file, pos, buf, bytes);
	}
	for (uint8_t i = 0; i < 4; i++) {
		if (!RAND_bytes(reinterpret_cast<uint8_t *>(buf), bytes))
			throw Ssl_error();
		write_pattern(file, pos, buf, bytes);
	}

	return file;
}
