#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

#include "cipher.hpp"
#include "crypt.hpp"
#include "hash.hpp"
#include "hmac.hpp"
#include "luks.hpp"

char *prog;

namespace test {

using namespace fluks;

uint8_t
dehex(char c)
{
	if ('0' <= c && c <= '9')
		return c - '0';
	if ('A' <= c && c <= 'F')
		return 10 + c - 'A';
	if ('a' <= c && c <= 'f')
		return 10 + c - 'a';
	Assert(0, std::string("bad hex character: ") + c);
	return 0;
}

void
dehex(const std::string &hex, uint8_t *buf)
{
	char byte[2];
	for (size_t i = 0; i < hex.size(); i++) {
		byte[i&1] = hex[i];
		if (i & 1) {
			*buf++ = dehex(byte[0]) << 4 | dehex(byte[1]);
		}
	}
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

class Test {
public:
	virtual void run() = 0;
};

class Cipher_test : public Test {
public:
	Cipher_test(cipher_type, const uint8_t *key, size_t sz_key,
	    const uint8_t *block, size_t sz_blk, crypt_direction);

	void run();
private:
	cipher_type _type;
	crypt_direction _dir;
	std::unique_ptr<uint8_t> _key;
	std::unique_ptr<uint8_t> _block;
	size_t _sz_key;
};

Cipher_test::Cipher_test(cipher_type type, const uint8_t *key, size_t sz_key,
    const uint8_t *block, size_t sz_blk, crypt_direction dir) :
	_type(type),
	_dir(dir),
	_key(new uint8_t[sz_key]),
	_block(new uint8_t[Cipher_traits::traits(type)->block_size]),
	_sz_key(sz_key)
{
	Assert(Cipher_traits::traits(type)->block_size == sz_blk,
	    "Cipher_test block size wrong");
	std::copy(key, key + sz_key, _key.get());
	std::copy(block, block + sz_blk, _block.get());
}

void
Cipher_test::run()
{
	std::shared_ptr<Cipher> cipher = Cipher::create(_type);
	uint8_t buf[cipher->traits()->block_size];
	cipher->init(_key.get(), _sz_key);
	if (_dir == DIR_ENCRYPT)
		cipher->encrypt(_block.get(), buf);
	else
		cipher->decrypt(_block.get(), buf);

	std::cout
	//    << "KEY=" << hex(_key.get(), _sz_key) << '\n'
	//    << (_dir == DIR_ENCRYPT ? 'P' : 'C') << "T="
	//    << hex(_block.get(), cipher->traits()->block_size) << '\n'
	//    << (_dir == DIR_ENCRYPT ? 'C' : 'P') << "T="
	    << hex(buf, cipher->traits()->block_size) << '\n';
}

class Hash_test : public Test {
public:
	Hash_test(hash_type type, const uint8_t *data, size_t sz);
	void run();

private:
	hash_type _type;
	std::unique_ptr<uint8_t> _data;
	size_t _sz;
};

Hash_test::Hash_test(hash_type type, const uint8_t *data, size_t sz) :
	_type(type),
	_data(new uint8_t[sz]),
	_sz(sz)
{
	std::copy(data, data + sz, _data.get());
}

void
Hash_test::run()
{
	std::shared_ptr<Hash_function> hash = Hash_function::create(_type);
	uint8_t buf[hash->traits()->digest_size];
	hash->init();
	hash->add(_data.get(), _sz);
	hash->end(buf);

	std::cout
	//    << "DATA=" << hex(_data.get(), _sz) << '\n'
	//    << "DIGEST="
	    << hex(buf, hash->traits()->digest_size) << '\n';
}

class Hmac_test : public Test {
public:
	Hmac_test(hash_type type, const uint8_t *key, size_t sz_key,
	    const uint8_t *data, size_t sz_data);
	void run();

private:
	hash_type _type;
	std::unique_ptr<uint8_t> _key;
	std::unique_ptr<uint8_t> _data;
	size_t _sz_key;
	size_t _sz_data;
};

Hmac_test::Hmac_test(hash_type type, const uint8_t *key, size_t sz_key,
    const uint8_t *data, size_t sz_data) :
	_type(type),
	_key(new uint8_t[sz_key]),
	_data(new uint8_t[sz_data]),
	_sz_key(sz_key),
	_sz_data(sz_data)
{
	std::copy(key, key + sz_key, _key.get());
	std::copy(data, data + sz_data, _data.get());
}

void
Hmac_test::run()
{
	std::shared_ptr<Hmac_function> hmac = Hmac_function::create(_type);
	uint8_t buf[hmac->traits()->digest_size];
	hmac->init(_key.get(), _sz_key);
	hmac->add(_data.get(), _sz_data);
	hmac->end(buf);

	std::cout << "KEY=" << hex(_key.get(), _sz_key)
	    << "\nDATA=" << hex(_data.get(), _sz_data)
	    << "\nDIGEST=" << hex(buf, hmac->traits()->digest_size) << '\n';
}

} // end test namespace

void
usage()
{
	std::cout
	    << "usage: " << prog
		<< " cipher TYPE (encrypt | decrypt) KEY DATA\n"
	    << "       " << prog << " hash TYPE DATA\n"
	    << "       " << prog << " hmac TYPE KEY DATA\n\n"
	    << "TYPE: name of the cipher/hash function\n"
	    << "KEY: key in hex\n"
	    << "DATA: data in hex; can also be plain text if preceded\n"
	    << "    immediately by a '-' character\n"
	    << "Result is the ciphertext/plaintext, hash digest,\n"
	    << "    or hmac digest\n";
}

int
main(int argc, char **argv)
{
	using namespace fluks;
	using namespace test;

	std::unique_ptr<Test> test;

	prog = *argv;
	if (argc < 2) {
		usage();
		return 1;
	}

	std::string type = argv[1];
	if (type == "cipher") {
		if (argc != 6) {
			usage();
			return 1;
		}
		std::string cipher = argv[2];
		std::string dir = argv[3];
		std::string key = argv[4];
		std::string data = argv[5];

		cipher_type cipher_ = Cipher_traits::type(cipher);
		Assert(cipher_ != CT_UNDEFINED, "undefined cipher: " + cipher);
		crypt_direction dir_;
		if (dir == "encrypt")
			dir_ = crypt_direction::ENCRYPT;
		else if (dir == "decrypt")
			dir_ = crypt_direction::DECRYPT;
		else {
			Assert(0, "undefined crypt direction: " + dir);
			return 1; // won't return
		}
		uint8_t keybuf[key.size()/2];
		dehex(key, keybuf);
		uint8_t databuf[data.size()];
		size_t datasz;
		if (data[0] == '-') {
			std::copy(data.begin() + 1, data.end(),
			    reinterpret_cast<char *>(databuf));
			datasz = data.size()-1;
		} else {
			dehex(data, databuf);
			datasz = data.size()/2;
		}

		test.reset(new Cipher_test(cipher_, keybuf, key.size()/2,
		    databuf, datasz, dir_));
	} else if (type == "hash") {
		if (argc != 4) {
			usage();
			return 1;
		}
		std::string hash = argv[2];
		std::string data = argv[3];

		hash_type hash_type = Hash_traits::type(hash);
		Assert(hash_type != HT_UNDEFINED, "undefined hash: " + hash);
		uint8_t databuf[data.size()];
		size_t datasz;
		if (data[0] == '-') {
			std::copy(data.begin() + 1, data.end(),
			    reinterpret_cast<char *>(databuf));
			datasz = data.size()-1;
		} else {
			dehex(data, databuf);
			datasz = data.size()/2;
		}

		test.reset(new Hash_test(hash_type, databuf, datasz));
	} else if (type == "hmac") {
		if (argc != 5) {
			usage();
			return 1;
		}
		std::string hash = argv[2];
		std::string key = argv[3];
		std::string data = argv[4];

		hash_type hash_ = Hash_traits::type(hash);
		Assert(hash_ != HT_UNDEFINED, "undefined hash: " + hash);
		uint8_t keybuf[key.size()/2];
		dehex(key, keybuf);
		uint8_t databuf[data.size()];
		size_t datasz;
		if (data[0] == '-') {
			std::copy(data.begin() + 1, data.end(),
			    reinterpret_cast<char *>(databuf));
			datasz = data.size()-1;
		} else {
			dehex(data, databuf);
			datasz = data.size()/2;
		}

		test.reset(new Hmac_test(hash_, keybuf, key.size()/2,
		    databuf, datasz));
	} else
		Assert(0, "undefined test type: " + type);

	test->run();

	return 0;
}
