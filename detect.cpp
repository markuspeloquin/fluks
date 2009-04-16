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

#include <fstream>
#include <iostream>
#include <sstream>
#include <tr1/cstdint>
#include <boost/regex.hpp>

#include "detect.hpp"
#include "hash.hpp"

namespace fluks {
namespace {

struct cipher_stats {
	uint16_t blocksize;
	uint16_t key_min;
	uint16_t key_max;
	uint16_t key_step;
};

/** Singleton to parse /proc/crypto for supported ciphers and hashes */
class Crypto_detect {
public:
	static Crypto_detect *instance()
	{	return &_instance; }

	// detected from /proc/crypto
	std::set<std::string> ciphers;
	std::set<std::string> hashes;

private:
	Crypto_detect();
	~Crypto_detect() {}

	Crypto_detect(const Crypto_detect &c) {}
	void operator=(const Crypto_detect &c) {}

	static Crypto_detect _instance;

};

Crypto_detect::Crypto_detect()
{
	std::ifstream file_in("/proc/crypto");
	// can't throw an exception
	if (!file_in) return;

	boost::regex expr("(.+?)\\s*:\\s(.+)");

	std::string line;
	std::string name;
	std::string type;
	while (file_in) {
		if (!std::getline(file_in, line)) break;

		if (line.empty()) {
			// empty line signifies the end of a crypto
			// description
			if (type == "cipher")
				ciphers.insert(name);
			else if (type == "digest")
				hashes.insert(name);

			name = "";
			type = "";
		} else {
			boost::smatch matches;
			if (!boost::regex_match(line, matches, expr)) {
				std::cerr << "/proc/crypto match failed: "
				    << line << '\n';
				continue;
			}
			if (matches[1] == "name") name = matches[2];
			else if (matches[1] == "type") type = matches[2];
		}
	}
}

Crypto_detect Crypto_detect::_instance;

} // end anon namespace
}


const std::set<std::string> &
fluks::system_ciphers()
{
	return Crypto_detect::instance()->ciphers;
}

const std::set<std::string> &
fluks::system_hashes()
{
	return Crypto_detect::instance()->hashes;
}
