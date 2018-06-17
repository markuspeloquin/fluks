#include <libgen.h>
#include <unistd.h>

#include <fstream>
#include <regex>

#include "common.hpp"
#include "../serpent.h"

char *prog;

namespace test {

enum class test_type { monte_carlo, table, variable_key, variable_txt };

bool
run(uint16_t i, const uint8_t *key, uint16_t szkey,
    const uint8_t pt[SERPENT_BLOCK], const uint8_t ct[SERPENT_BLOCK],
    test_type type, bool encrypt) {
	uint8_t buf[SERPENT_BLOCK];
	serpent_ctx ctx;
	const uint8_t *correct;

	if (serpent_init(&ctx, key, szkey) == SERPENT_BAD_KEY_MAT) {
		std::cerr << prog << ": bad key size: " << szkey << '\n';
		return false;
	}

	uint16_t iter = type == test_type::monte_carlo ? 10000 : 1;

	if (encrypt) {
		correct = ct;
		serpent_encrypt(&ctx, pt, buf);
		for (uint16_t i = 1; i < iter; i++)
			serpent_encrypt(&ctx, buf, buf);
	} else {
		correct = pt;
		serpent_decrypt(&ctx, ct, buf);
		for (uint16_t i = 1; i < iter; i++)
			serpent_decrypt(&ctx, buf, buf);
	}

	if (!std::equal(correct, correct + SERPENT_BLOCK, buf)) {
		std::cout << '\n' << std::setw(2) << i << " FAIL: "
		    << hex(correct, SERPENT_BLOCK)
		    << "\n    got: " << hex(buf, SERPENT_BLOCK) << '\n';
		return false;
	}

	switch (type) {
	case test_type::table:
	case test_type::variable_key:
	case test_type::variable_txt:
		// do opposite direction for known_answer
		if (encrypt) {
			correct = pt;
			serpent_decrypt(&ctx, ct, buf);
		} else {
			correct = ct;
			serpent_encrypt(&ctx, pt, buf);
		}

		if (!std::equal(correct, correct + SERPENT_BLOCK, buf)) {
			std::cout << std::setw(2) << i << " FAIL: "
			    << hex(correct, SERPENT_BLOCK)
			    << "\n    got: " << hex(buf, SERPENT_BLOCK)
			    << '\n';
			return false;
		}
	default:;
	}

	return true;
}

void
reverse(uint8_t *buf, size_t sz) {
	size_t i = 0;
	size_t j = sz - 1;
	while (i < j) {
		uint8_t t = buf[j];
		buf[j--] = buf[i];
		buf[i++] = t;
	}
}

bool
run_script(const std::string &path, test_type type) {
	std::ifstream file(path.c_str());
	if (!file) {
		std::cerr << prog << ": failed to open file " << path << '\n';
		return false;
	}

	uint8_t key[SERPENT_KEYMAX];
	uint8_t ct[SERPENT_BLOCK];
	uint8_t pt[SERPENT_BLOCK];
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
			reverse(key, keysize);
		} else if (prop == "CT") {
			if (value.size() != SERPENT_BLOCK * 2 ||
			    !std::regex_match(value, re_hex)) {
				std::cerr << "bad ct\n";
				continue;
			}
			dehex(value, ct);
			reverse(ct, SERPENT_BLOCK);
			encrypt = true;
		} else if (prop == "PT") {
			if (value.size() != SERPENT_BLOCK * 2 ||
			    !std::regex_match(value, re_hex)) {
				std::cerr << "bad pt\n";
				continue;
			}
			dehex(value, pt);
			reverse(pt, SERPENT_BLOCK);
			encrypt = false;
		}
	}

	return all_good;
}

}

// usage: ./serpent [DIR]
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

	// these two tests take a minute to complete each
#if 0
	if (verbose)
		std::cerr << '(' << base << ": Monte Carlo decrypt "
		    "[takes about a minute])\n";
	all_good &= run_script("serpent_mc_dec.txt", monte_carlo);

	if (verbose)
		std::cerr << '(' << base  << ": Monte Carlo encrypt "
		    "[takes about a minute])\n";
	all_good &= run_script("serpent_mc_enc.txt", monte_carlo);
#endif

	if (verbose)
		std::cerr << '(' << base  << ": variable key, known text)\n";
	all_good &= run_script("serpent_varkey.txt", test_type::variable_key);

	if (verbose)
		std::cerr << '(' << base  << ": variable text, known key)\n";
	all_good &= run_script("serpent_vartxt.txt", test_type::variable_txt);

	if (verbose)
		std::cerr << '(' << base  << ": table, known text)\n";
	all_good &= run_script("serpent_table.txt", test_type::table);

	return all_good ? 0 : 1;
}
