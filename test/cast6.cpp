#include <unistd.h>

#include <fstream>
#include <boost/regex.hpp>

#include "common.hpp"
#include "../cast6.h"

char *prog;
extern uint8_t cast6_iv_rotk[12][4];
extern uint32_t cast6_iv_mask[12][4];
extern uint8_t cast6_iv_out[12][CAST6_BLOCK];

extern "C" void
	cast6_encrypt_test(const struct cast6_ctx *,
	    const uint8_t[16], uint8_t[16], uint8_t);
extern "C" void
	cast6_decrypt_test(const struct cast6_ctx *,
	    const uint8_t[16], uint8_t[16], uint8_t);

namespace test {

inline std::string rotk_string(const uint8_t rotk[4])
{
	return hex(rotk, 4);
}

std::string mask_string(const uint32_t mask[4])
{
	std::ostringstream out;
	out << std::setfill('0') << std::hex;
	for (uint8_t i = 0; i < 4; i++) {
		if (i) out << ' ';
		out << std::setw(8) << mask[i];
	}
	return out.str();
}

bool check(uint8_t round,
    const uint8_t rotk[4],
    const uint32_t mask[4],
    const uint8_t out[CAST6_BLOCK])
{
	uint8_t i = round-1;

	if (!std::equal(rotk, rotk + 4, cast6_iv_rotk[i])) {
		std::cerr << '\n' << "ROTK FAIL: " << rotk_string(rotk)
		    << "\n      got: " << rotk_string(cast6_iv_rotk[i])
		    << '\n';
		return false;
	}
	if (!std::equal(mask, mask + 4, cast6_iv_mask[i])) {
		std::cerr << '\n' << "MASK FAIL: " << mask_string(mask)
		    << "\n      got: " << mask_string(cast6_iv_mask[i])
		    << '\n';
		return false;
	}
	if (!std::equal(out, out + CAST6_BLOCK, cast6_iv_out[i])) {
		std::cerr << '\n' << "OUT FAIL: " << hex(out, CAST6_BLOCK)
		    << "\n     got: " << hex(cast6_iv_out[i], CAST6_BLOCK)
		    << '\n';
		return false;
	}
	return true;
}

bool run(const uint8_t *key, uint16_t szkey, const uint8_t in[CAST6_BLOCK],
    bool encrypt)
{
	uint8_t buf[CAST6_BLOCK];
	cast6_ctx ctx;

	if (!cast6_init(&ctx, key, szkey)) {
		std::cerr << prog << ": bad key size: " << szkey << '\n';
		return false;
	}

	if (encrypt)
		cast6_encrypt(&ctx, in, buf);
	else
		cast6_decrypt(&ctx, in, buf);
	return true;
}

bool run_script(const std::string &path)
{
	std::ifstream file(path.c_str());
	if (!file) {
		std::cerr << prog << ": failed to open file " << path << '\n';
		return false;
	}

	uint8_t key[CAST6_KEY_MAX];
	uint8_t in[CAST6_BLOCK];
	uint8_t out[CAST6_BLOCK];
	uint8_t rotk[4];
	uint32_t mask[4];
	size_t keysize = 0;
	uint8_t round = 0;
	bool all_good = true;
	bool encrypt = false;

	boost::regex re_keysize("KEYSIZE=(128|192|256)");
	boost::regex re_key("KEY=([0-9A-Fa-f]+)");
	boost::regex re_pt("PT=([0-9A-Fa-f]{32})");
	boost::regex re_ct("CT=([0-9A-Fa-f]{32})");
	boost::regex re_out("OUT=([0-9A-Fa-f]{32})");
	boost::regex re_round("R=([0-9]+)");
	boost::regex re_rotk(
	    "ROTK1=([0-9A-Fa-f]{2}) +"
	    "ROTK2=([0-9A-Fa-f]{2}) +"
	    "ROTK3=([0-9A-Fa-f]{2}) +"
	    "ROTK4=([0-9A-Fa-f]{2})");
	boost::regex re_mask(
	    "MASK1=([0-9A-Fa-f]{8}) +"
	    "MASK2=([0-9A-Fa-f]{8}) +"
	    "MASK3=([0-9A-Fa-f]{8}) +"
	    "MASK4=([0-9A-Fa-f]{8})");

	while (file) {
		std::string line;
		std::getline(file, line);
		if (file.bad()) {
			std::cerr << prog << ": bad stream\n";
			break;
		}

		boost::smatch matches;
		if (boost::regex_match(line, matches, re_keysize)) {
			std::string s = matches[1];
			keysize = atoi(s.c_str()) / 8;
		} else if (boost::regex_match(line, matches, re_key)) {
			std::string s = matches[1];
			if (s.size() != keysize * 2) continue;
			dehex(s, key);
		} else if (boost::regex_match(line, matches, re_pt)) {
			std::string s = matches[1];
			dehex(s, in);
			encrypt = true;
		} else if (boost::regex_match(line, matches, re_ct)) {
			std::string s = matches[1];
			dehex(s, in);
			encrypt = false;
		} else if (boost::regex_match(line, matches, re_out)) {
			std::string s = matches[1];
			dehex(s, out);
			all_good &= check(round, rotk, mask, out);
		} else if (boost::regex_match(line, matches, re_round)) {
			std::string s = matches[1];
			round = atoi(s.c_str());
			if (round == 1)
				all_good &= run(key, keysize, in, encrypt);
		} else if (boost::regex_match(line, matches, re_rotk)) {
			std::string s = matches[1];
			rotk[0] = strtol(s.c_str(), 0, 16);
			s = matches[2];
			rotk[1] = strtol(s.c_str(), 0, 16);
			s = matches[3];
			rotk[2] = strtol(s.c_str(), 0, 16);
			s = matches[4];
			rotk[3] = strtol(s.c_str(), 0, 16);
		} else if (boost::regex_match(line, matches, re_mask)) {
			// strtol() cannot handle unsigned integers with
			// the most significant bit a '1'
			std::string s = matches[1];
			mask[0] = strtoll(s.c_str(), 0, 16);
			s = matches[2];
			mask[1] = strtoll(s.c_str(), 0, 16);
			s = matches[3];
			mask[2] = strtoll(s.c_str(), 0, 16);
			s = matches[4];
			mask[3] = strtoll(s.c_str(), 0, 16);
		} else
			continue;
	}

	return all_good;
}

}

// usage: ./serpent [DIR]
// DIR contains the test scripts
int main(int argc, char **argv)
{
	using namespace test;

	prog = *argv;

	if (argc > 1 && chdir(argv[1]) == -1) {
		perror(prog);
		return 1;
	}

	bool all_good = run_script("cast6.txt");

	return all_good ? 0 : 1;
}
