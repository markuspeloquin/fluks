#include <fstream>
#include <iostream>
#include <sstream>
#include <boost/regex.hpp>

#include "detect.hpp"

luks::Crypto_detect::Crypto_detect() :
	_good(false)
{
	std::ifstream file_in("/proc/crypto");
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
			if (type == "blkcipher")
				_blk_ciphers.insert(name);
			else if (type == "givcipher")
				_iv_ciphers.insert(name);
			else if (type == "digest")
				_hashes.insert(name);

			name = "";
			type = "";
		} else {
			boost::smatch matches;
			if (!boost::regex_match(line, matches, expr)) {
				std::cerr << "/proc/crypto match failed: " << line << '\n';
				continue;
			}
			if (matches[1] == "name") name = matches[2];
			else if (matches[1] == "type") type = matches[2];
		}
	}
}

luks::Crypto_detect luks::Crypto_detect::_instance;
