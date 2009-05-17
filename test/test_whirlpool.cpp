#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>
#include <boost/scoped_array.hpp>

#include "../errors.hpp"
#include "../whirlpool.h"

char *prog;

namespace test {

using namespace fluks;

uint8_t
dehex(char c)
{
	if ('0' <= c && c <= '9')	return c - '0';
	if ('A' <= c && c <= 'F')	return 10 + c - 'A';
	if ('a' <= c && c <= 'f')	return 10 + c - 'a';
	Assert(0, std::string("bad hex character: ") + c);
	return 0;
}

uint8_t *
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

struct Test {
	Test() : buf(0) {}

	Test(const std::string &str, const uint8_t res[WHIRLPOOL_SZ_DIGEST]) :
		buf(new uint8_t[str.size()]),
		sz(str.size())
	{
		std::copy(str.begin(), str.end(),
		    reinterpret_cast<char *>(this->buf.get()));
		std::copy(res, res + WHIRLPOOL_SZ_DIGEST, this->res);
	}

	Test(const uint8_t *buf, size_t sz,
	    const uint8_t res[WHIRLPOOL_SZ_DIGEST]) :
		buf(new uint8_t[sz]),
		sz(sz)
	{
		std::copy(buf, buf + sz, this->buf.get());
		std::copy(res, res + WHIRLPOOL_SZ_DIGEST, this->res);
	}

	Test(const Test &t) :
		buf(new uint8_t[t.sz]),
		sz(t.sz)
	{
		std::copy(t.buf.get(), t.buf.get() + sz, buf.get());
		std::copy(t.res, t.res + WHIRLPOOL_SZ_DIGEST, res);
		std::copy(t.res0, t.res0 + WHIRLPOOL_SZ_DIGEST, res0);
	}

	Test &operator=(const Test &t)
	{
		Test c = t;
		std::swap(*this, c);
		return *this;
	}

	bool run()
	{
		whirlpool_ctx ctx;
		whirlpool_init(&ctx);
		whirlpool_update(&ctx, buf.get(), sz);
		whirlpool_end(&ctx, res0, WHIRLPOOL_SZ_DIGEST);
		return std::equal(res, res + WHIRLPOOL_SZ_DIGEST, res0);
	}

	boost::scoped_array<uint8_t> buf;
	size_t sz;
	uint8_t res[WHIRLPOOL_SZ_DIGEST];
	uint8_t res0[WHIRLPOOL_SZ_DIGEST];
};

}

int
main(int argc, char **argv)
{
	using namespace test;
	prog = *argv;

	uint8_t digestbuf[WHIRLPOOL_SZ_DIGEST];

	std::vector<Test> tests;

	tests.push_back(Test("", dehex(
	    "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7"
	    "3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
	    digestbuf)));

	tests.push_back(Test("a", dehex(
	    "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42"
	    "d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a",
	    digestbuf)));

	tests.push_back(Test("abc", dehex(
	    "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c"
	    "7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
	    digestbuf)));

	tests.push_back(Test("message digest", dehex(
	    "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b"
	    "8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e",
	    digestbuf)));

	std::string alpha_lower = "abcdefghijklmnopqrstuvwxyz";
	std::string alpha_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	std::string digits = "0123456789";

	tests.push_back(Test(alpha_lower, dehex(
	    "f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b"
	    "08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b",
	    digestbuf)));

	tests.push_back(Test(alpha_upper + alpha_lower + digits, dehex(
	    "dc37e008cf9ee69bf11f00ed9aba26901dd7c28cdec066cc6af42e40f82f3a1e"
	    "08eba26629129d8fb7cb57211b9281a65517cc879d7b962142c65f5a7af01467",
	    digestbuf)));

	std::string text;
	for (uint8_t i = 0; i < 8; i++) text += "1234567890";
	tests.push_back(Test(text, dehex(
	    "466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549c4afadb601429"
	    "4d5bd8df2a6c44e538cd047b2681a51a2c60481e88c5a20b2c2a80cf3a9a083b",
	    digestbuf)));

	tests.push_back(Test(
	    "abcdbcdecdefdefgefghfghighijhijk", dehex(
	    "2a987ea40f917061f5d6f0a0e4644f488a7a5a52deee656207c562f988e95c69"
	    "16bdc8031bc5be1b7b947639fe050b56939baaa0adff9ae6745b7b181c3be3fd",
	    digestbuf)));

	text.clear();
	for (uint32_t i = 0; i < 1000000; i++) text += 'a';
	tests.push_back(Test(text, dehex(
	    "0c99005beb57eff50a7cf005560ddf5d29057fd86b20bfd62deca0f1ccea4af5"
	    "1fc15490eddc47af32bb2b66c34ff9ad8c6008ad677f77126953b226e4ed8b01",
	    digestbuf)));

	bool all_good = true;
	for (std::vector<Test>::iterator i = tests.begin();
	    i != tests.end(); ++i) {
		if (!i->run()) {
			all_good = false;
			std::cout << prog << ": test " << i - tests.begin()
			    << " failed\n";
			std::cout << "  " << hex(i->res, WHIRLPOOL_SZ_DIGEST)
			    << "\n  " << hex(i->res0, WHIRLPOOL_SZ_DIGEST)
			    << '\n';
		}
	}
	if (all_good) {
		std::cout << prog << ": all tests passed\n";
		return 0;
	}
	return 1;
}
