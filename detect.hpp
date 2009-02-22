#ifndef DETECT_HPP
#define DETECT_HPP

#include <set>
#include <string>

#include "errors.hpp"

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


/** Checks if a cipher spec is supported by the kernel.
 *
 * \param cipher	The name of the cipher (e.g. aes, twofish).
 * \param chainmode	The block chain mode (e.g. cbc, ecb).
 * \param ivopts	IV option (e.g. plain, essiv).
 * \param ivmode	IV mode (i.e. a hash spec for cbc-essiv).
 * \return	Whether or not the cipher spec is supported.
 */
void	cipher_spec_check(const std::string &cipher,
	    const std::string &chainmode, const std::string &ivopts,
	    const std::string &ivmode)
	throw (Bad_spec);

/** Checks if a hash spec is supported by the kernel.
 *
 * \param hash	The hash spec (e.g. sha256, rmd160).
 * \return	Whether or not the hash spec is supported.
 */
void	hash_spec_check(const std::string &hash) throw (Bad_spec);

}

#endif
