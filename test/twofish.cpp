#include <libgen.h>
#include <unistd.h>

#include <fstream>
#include <regex>

#include "common.hpp"
#include "../twofish.h"

char *prog;

namespace test {

enum class test_type { monte_carlo, table, variable_key, variable_txt };

bool
run(uint16_t i, const uint8_t *key, uint16_t szkey,
    const uint8_t pt[TWOFISH_BLOCK], const uint8_t ct[TWOFISH_BLOCK],
    test_type type, bool encrypt) {
	uint8_t buf[TWOFISH_BLOCK];
	twofish_ctx ctx;
	const uint8_t *correct;

	if (!twofish_init(&ctx, key, szkey)) {
		std::cerr << prog << ": bad key size: " << szkey << '\n';
		return false;
	}

	uint16_t iter = type == test_type::monte_carlo ? 10000 : 1;

	if (encrypt) {
		correct = ct;
		twofish_encrypt(&ctx, pt, buf);
		for (uint16_t i = 1; i < iter; i++)
			twofish_encrypt(&ctx, buf, buf);
	} else {
		correct = pt;
		twofish_decrypt(&ctx, ct, buf);
		for (uint16_t i = 1; i < iter; i++)
			twofish_decrypt(&ctx, buf, buf);
	}

	if (!std::equal(correct, correct + TWOFISH_BLOCK, buf)) {
		std::cout << '\n' << std::setw(2) << i << " FAIL: "
		    << hex(correct, TWOFISH_BLOCK)
		    << "\n    got: " << hex(buf, TWOFISH_BLOCK) << '\n';
		return false;
	}

	switch (type) {
	case test_type::table:
	case test_type::variable_key:
	case test_type::variable_txt:
		// do opposite direction for known_answer
		if (encrypt) {
			correct = pt;
			twofish_decrypt(&ctx, ct, buf);
		} else {
			correct = ct;
			twofish_encrypt(&ctx, pt, buf);
		}

		if (!std::equal(correct, correct + TWOFISH_BLOCK, buf)) {
			std::cout << std::setw(2) << i << " FAIL: "
			    << hex(correct, TWOFISH_BLOCK)
			    << "\n    got: " << hex(buf, TWOFISH_BLOCK)
			    << '\n';
			return false;
		}
	default:;
	}

	return true;
}

bool
run_script(const std::string &path, test_type type) {
	std::ifstream file(path.c_str());
	if (!file) {
		std::cerr << prog << ": failed to open file " << path << '\n';
		return false;
	}

	uint8_t key[TWOFISH_KEYMAX];
	uint8_t ct[TWOFISH_BLOCK];
	uint8_t pt[TWOFISH_BLOCK];
	size_t keysize = 0;
	uint16_t i = 0;
	bool all_good = true;
	bool have_job = false;
	bool encrypt = false;

	std::regex expr("(KEYSIZE|I|KEY|CT|PT)=(.*)");
	std::regex re_digits("([0-9]+).*");
	std::regex re_hex("[0-9A-Fa-f]+");
	std::regex re_keysize("(128|192|256)");

	while (file) {
		std::string line;
		std::getline(file, line);
		if (file.bad()) {
			std::cerr << prog << ": bad stream\n";
			break;
		}

		std::smatch matches;
		if (!std::regex_match(line, matches, expr)) continue;
		std::string prop = matches[1];
		std::string value = matches[2];
		if (prop == "KEYSIZE") {
			if (!std::regex_match(value, re_keysize))
				std::cerr << "bad key size\n";
			else {
				keysize = atoi(value.c_str()) / 8;
				have_job = false;
			}
		}

		if (prop == "I") {
			std::smatch i_match;
			if (!std::regex_match(value, i_match, re_digits)) {
				std::cerr << "bad number\n";
				continue;
			}
			if (have_job) {
				if (!run(i, key, keysize, pt, ct,
				    type, encrypt))
					all_good = false;
			}

			std::string i_str = i_match[1];
			i = atoi(i_str.c_str());
			have_job = true;
		} else if (prop == "KEY") {
			if (value.size() != keysize * 2 ||
			    !std::regex_match(value, re_hex)) {
				std::cerr << "bad key\n";
				continue;
			}
			dehex(value, key);
		} else if (prop == "CT") {
			if (value.size() != TWOFISH_BLOCK * 2 ||
			    !std::regex_match(value, re_hex)) {
				std::cerr << "bad ct\n";
				continue;
			}
			dehex(value, ct);
			encrypt = true;
		} else if (prop == "PT") {
			if (value.size() != TWOFISH_BLOCK * 2 ||
			    !std::regex_match(value, re_hex)) {
				std::cerr << "bad pt\n";
				continue;
			}
			dehex(value, pt);
			encrypt = false;
		}
	}

	return all_good;
}

}

// usage: ./twofish [DIR]
// DIR contains the test scripts
int
main(int argc, char **argv) {
	using namespace test;

	prog = *argv;

	if (argc > 1 && chdir(argv[1]) == -1) {
		perror(prog);
		return 1;
	}
	
	bool verbose = false;
	char *base = basename(prog);
	bool all_good = true;

	// these tests take about 10s to complete each
	/*
	if (verbose)
		std::cerr << '(' << base << ": Monte Carlo decrypt "
		    "[takes about 10s])\n";
	all_good &= run_script("twofish_mc_dec.txt", monte_carlo);

	if (verbose)
		std::cerr << '(' << base  << ": Monte Carlo encrypt "
		    "[takes about 10s])\n";
	all_good &= run_script("twofish_mc_enc.txt", monte_carlo);
	*/

	if (verbose)
		std::cerr << '(' << base  << ": variable key, known text)\n";
	all_good &= run_script("twofish_varkey.txt", test_type::variable_key);

	if (verbose)
		std::cerr << '(' << base  << ": variable text, known key)\n";
	all_good &= run_script("twofish_vartxt.txt", test_type::variable_txt);

	if (verbose)
		std::cerr << '(' << base  << ": table, known text)\n";
	all_good &= run_script("twofish_table.txt", test_type::table);

	return all_good ? 0 : 1;
}
