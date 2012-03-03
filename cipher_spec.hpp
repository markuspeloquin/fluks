/* Copyright (c) 2009-2010, Markus Peloquin <markus@cs.wisc.edu>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef CIPHER_SPEC_HPP
#define CIPHER_SPEC_HPP

#include <string>

#include "errors.hpp"

namespace fluks {

/** Ciphers supported by <em>fluks</em> */
enum cipher_type {
	CT_UNDEFINED = 0,
	CT_AES,
	CT_BLOWFISH,
#ifndef OPENSSL_NO_CAMELLIA
	CT_CAMELLIA,
#endif
	CT_CAST5,
	CT_CAST6,
	CT_TWOFISH,
	CT_SERPENT
};

/** Cipher block modes supported by <em>fluks</em> */
enum block_mode {
	BM_UNDEFINED = 0,
	BM_CBC, /**< Cipher-block chaining */
	BM_CFB, /**< Cipher feedback */
	BM_CTR, /**< Counter */
	/** Cipher Text Stealing
	 *
	 * Described in RFC 2040, Section 8 */
	BM_ECB, /**< Electronic codebook */
	BM_OFB, /**< Output feedback */
	BM_PCBC /**< Propogating cipher-block chaining */
};

enum iv_mode {
	IM_UNDEFINED = 0,
	IM_PLAIN,
	IM_ESSIV
};

/** Hash types supported by <em>fluks</em>
 *
 * Tiger is optimized for 64-bit architectures, designed by the same folks
 * who brought you the Serpent cipher. Tiger/{128,160} are just truncated
 * versions of Tiger/192.
 *
 * Along with SHA-{1,256,384,512} and RMD-{128,160}, WHIRLPOOL is included
 * in ISO/IEC's list of recommended hash functions (10118-3), and is
 * also recommended by NESSIE. WHIRLPOOL-{256,384} are just truncated
 * versions.
 */
enum hash_type {
	HT_UNDEFINED = 0,
	HT_MD5,	/**< (you probably should not use this) */
	HT_RMD160,	/**< Possibly better knows as RIPEMD-160 */
	HT_SHA1,
	HT_SHA224,
	HT_SHA256,
	HT_SHA384,
	HT_SHA512,
	HT_TIGER128,
	HT_TIGER160,
	HT_TIGER192,
	HT_WHIRLPOOL256,
	HT_WHIRLPOOL384,
	HT_WHIRLPOOL512
};

class Cipher_traits;
class Hash_traits;

class Cipher_spec {
public:
	Cipher_spec(ssize_t sz_key, const std::string &spec) throw (Bad_spec)
	{
		reset(sz_key, spec);
	}
	Cipher_spec(ssize_t sz_key, enum cipher_type cipher,
	    enum block_mode block_mode=BM_UNDEFINED,
	    enum iv_mode iv_mode=IM_UNDEFINED,
	    enum hash_type iv_hash=HT_UNDEFINED) throw (Bad_spec)
	{
		reset(sz_key, cipher, block_mode, iv_mode, iv_hash);
	}

	void reset(ssize_t sz_key, const std::string &spec) throw (Bad_spec);
	void reset(ssize_t sz_key, enum cipher_type cipher,
	    enum block_mode block_mode=BM_UNDEFINED,
	    enum iv_mode iv_mode=IM_UNDEFINED,
	    enum hash_type iv_hash=HT_UNDEFINED) throw (Bad_spec);

	enum cipher_type type_cipher() const
	{	return _ty_cipher; }
	enum block_mode type_block_mode() const
	{	return _ty_block_mode; }
	enum iv_mode type_iv_mode() const
	{	return _ty_iv_mode; }
	enum hash_type type_iv_hash() const
	{	return _ty_iv_hash; }

	const std::string &name_cipher() const
	{	return _nm_cipher; }
	const std::string &name_block_mode() const
	{	return _nm_block_mode; }
	const std::string &name_iv_mode() const
	{	return _nm_iv_mode; }
	const std::string &name_iv_hash() const
	{	return _nm_iv_hash; }

	std::string canon_cipher() const;
	std::string canon_mode() const;

private:
	void check_spec_support(const Cipher_traits *cipher_traits,
	    const Hash_traits *hash_traits) throw (Bad_spec);
	void check_spec(ssize_t sz_key) throw (Bad_spec);

	std::string		_nm_cipher;
	std::string		_nm_block_mode;
	std::string		_nm_iv_mode;
	std::string		_nm_iv_hash;
	enum cipher_type	_ty_cipher;
	enum block_mode		_ty_block_mode;
	enum iv_mode		_ty_iv_mode;
	enum hash_type		_ty_iv_hash;
};

}

#endif
