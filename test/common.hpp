#ifndef TEST_COMMON_HPP
#define TEST_COMMON_HPP

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace test {

inline uint8_t
dehex(char c)
{
	if ('0' <= c && c <= '9')	return c - '0';
	if ('A' <= c && c <= 'F')	return 10 + c - 'A';
	if ('a' <= c && c <= 'f')	return 10 + c - 'a';
	std::cerr << "bad hex character: " << c << '\n';
	exit(1);
}

inline uint8_t *
dehex(const std::string &hex, uint8_t *buf)
{
	char byte[2];
	uint8_t *start = buf;
	for (size_t i = 0; i < hex.size(); i++) {
		byte[i&1] = hex[i];
		if (i&1)
			*buf++ = dehex(byte[0]) << 4 | dehex(byte[1]);
	}
	return start;
}

std::string
hex(const uint8_t *buf, size_t sz)
{
	std::ostringstream out;
	out << std::hex << std::setfill('0');
	for (size_t i = 0; i < sz; i++) {
		if (i && i % 32 == 0)
			out << '\n';
		out << std::setw(2) << (short)buf[i];
	}
	return out.str();
}

}

#endif
