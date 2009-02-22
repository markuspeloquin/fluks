#ifndef DETECT_HPP
#define DETECT_HPP

#include <set>
#include <string>

namespace luks {

class Crypto_detect {
public:
	static const std::set<std::string> blk_ciphers()
	{	return _instance._blk_ciphers; }
	static const std::set<std::string> iv_ciphers()
	{	return _instance._iv_ciphers; }
	static const std::set<std::string> hashes()
	{	return _instance._hashes; }

	static bool good()
	{	return _instance._good; }

private:
	Crypto_detect();
	~Crypto_detect() {}

	Crypto_detect(const Crypto_detect &c) {}
	void operator=(const Crypto_detect &c) {}

	static Crypto_detect _instance;

	std::set<std::string> _blk_ciphers;
	std::set<std::string> _iv_ciphers;
	std::set<std::string> _hashes;
	bool _good;
};

}

#endif
