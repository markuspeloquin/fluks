#include <algorithm>
#include <vector>
#include <boost/scoped_array.hpp>

#include "common.hpp"
#include "../errors.hpp"
#include "../tiger.h"

char *prog;

namespace test {

struct Test {
	Test() : buf(0) {}

	Test(const std::string &str, const uint8_t res[TIGER_SZ_DIGEST]) :
		buf(new uint8_t[str.size()]),
		sz(str.size())
	{
		std::copy(str.begin(), str.end(),
		    reinterpret_cast<char *>(this->buf.get()));
		std::copy(res, res + TIGER_SZ_DIGEST, this->res);
	}

	Test(const uint8_t *buf, size_t sz,
	    const uint8_t res[TIGER_SZ_DIGEST]) :
		buf(new uint8_t[sz]),
		sz(sz)
	{
		std::copy(buf, buf + sz, this->buf.get());
		std::copy(res, res + TIGER_SZ_DIGEST, this->res);
	}

	Test(const Test &t) :
		buf(new uint8_t[t.sz]),
		sz(t.sz)
	{
		std::copy(t.buf.get(), t.buf.get() + sz, buf.get());
		std::copy(t.res, t.res + TIGER_SZ_DIGEST, res);
		std::copy(t.res0, t.res0 + TIGER_SZ_DIGEST, res0);
	}

	Test &operator=(const Test &t)
	{
		if (this == &t) return *this;
		sz = t.sz;
		buf.reset(new uint8_t[sz]);
		std::copy(t.buf.get(), t.buf.get() + sz, buf.get());
		std::copy(t.res, t.res + TIGER_SZ_DIGEST, res);
		std::copy(t.res0, t.res0 + TIGER_SZ_DIGEST, res0);
		return *this;
	}

	bool run()
	{
		tiger_ctx ctx;
		tiger_init(&ctx, 1);
		tiger_update(&ctx, buf.get(), sz);
		tiger_end(&ctx, res0, TIGER_SZ_DIGEST);
		return std::equal(res, res + TIGER_SZ_DIGEST, res0);
	}

	boost::scoped_array<uint8_t> buf;
	size_t sz;
	uint8_t res[TIGER_SZ_DIGEST]; // target hash
	uint8_t res0[TIGER_SZ_DIGEST]; // computed hash
};

}

int
main(int argc, char **argv)
{
	using namespace test;
	prog = *argv;

	uint8_t digestbuf[TIGER_SZ_DIGEST];

	std::vector<Test> tests;

	tests.push_back(Test("", dehex(
	    "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3", digestbuf)));

	tests.push_back(Test("a", dehex(
	    "77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809", digestbuf)));

	tests.push_back(Test("abc", dehex(
	    "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93", digestbuf)));

	tests.push_back(Test("message digest", dehex(
	    "d981f8cb78201a950dcf3048751e441c517fca1aa55a29f6", digestbuf)));

	std::string alpha_lower = "abcdefghijklmnopqrstuvwxyz";
	std::string alpha_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	std::string digits = "0123456789";

	tests.push_back(Test(alpha_lower, dehex(
	    "1714a472eee57d30040412bfcc55032a0b11602ff37beee9", digestbuf)));

	tests.push_back(Test(
	    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", dehex(
	    "0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e", digestbuf)));

	tests.push_back(Test(alpha_upper + alpha_lower + digits, dehex(
	    "8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc", digestbuf)));

	std::string text;
	for (uint8_t i = 0; i < 8; i++) text += "1234567890";
	tests.push_back(Test(text, dehex(
	    "1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd", digestbuf)));

	text.clear();
	for (uint32_t i = 0; i < 1000000; i++) text += 'a';
	tests.push_back(Test(text, dehex(
	    "6db0e2729cbead93d715c6a7d36302e9b3cee0d2bc314b41", digestbuf)));

	bool all_good = true;
	for (std::vector<Test>::iterator i = tests.begin();
	    i != tests.end(); ++i) {
		if (!i->run()) {
			all_good = false;
			std::cout << prog << ": test " << i - tests.begin()
			    << " failed\n";
			std::cout << "  " << hex(i->res, TIGER_SZ_DIGEST)
			    << "\n  " << hex(i->res0, TIGER_SZ_DIGEST) << '\n';
		}
	}

	return all_good ? 0 : 1;
}
