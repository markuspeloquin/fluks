/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <algorithm>
#include <functional>
#include <set>
#include <sstream>
#include <tr1/cstdint>
#include <boost/regex.hpp>

#include "cipher.hpp"
#include "crypt.hpp"
#include "detect.hpp"
#include "errors.hpp"
#include "hash.hpp"
#include "util.hpp"

namespace fluks {
namespace {

inline void
		check_spec(ssize_t, enum cipher_type, enum block_mode,
		    enum iv_mode, enum hash_type) throw (Bad_spec);
void		check_spec(ssize_t, enum cipher_type, enum block_mode,
		    enum iv_mode, enum hash_type,
		    const std::string &, const std::string &,
		    const std::string &, const std::string &)
		    throw (Bad_spec);
inline std::tr1::shared_ptr<Cipher>
		make_essiv_cipher(enum cipher_type, Hash_function *,
		    const uint8_t *key, size_t sz);
std::string	make_mode(const std::string &, const std::string &,
		    const std::string &);

inline std::tr1::shared_ptr<Cipher>
make_essiv_cipher(enum cipher_type type, Hash_function *hash,
    const uint8_t *key, size_t sz)
{
	std::tr1::shared_ptr<Cipher> cipher = Cipher::create(type);
	size_t sz_hash = hash->traits()->digest_size;
	uint8_t key_hash[sz_hash];

	// compute H(K)
	hash->init();
	hash->add(key, sz);
	hash->end(key_hash);

	// set key to H(K)
	cipher->init(key_hash, sz_hash);
	return cipher;
}

// reconstruct the mode string (e.g. 'cbc', 'cbc-essiv', 'cbc-essiv:sha256')
std::string
make_mode(const std::string &block_mode, const std::string &ivmode,
    const std::string &ivhash)
{
	std::ostringstream out;
	if (block_mode.size()) {
		out << block_mode;
		if (ivmode.size()) {
			out << '-' << ivmode;
			if (ivhash.size())
				out << ':' << ivhash;
		}
	}
	return out.str();
}

inline void
check_spec(ssize_t sz_key,
    enum cipher_type type_cipher, enum block_mode type_block_mode,
    enum iv_mode type_iv_mode, enum hash_type type_iv_hash) throw (Bad_spec)
{
	const Cipher_traits *cipher_traits = Cipher_traits::traits(
	    type_cipher);
	const Hash_traits *hash_traits = Hash_traits::traits(type_iv_hash);

	std::string name_cipher = cipher_traits->name;
	std::string name_block_mode = block_mode_info::name(type_block_mode);
	std::string name_iv_mode = iv_mode_info::name(type_iv_mode);
	std::string name_iv_hash = hash_traits->name;

	check_spec(sz_key,
	    type_cipher, type_block_mode, type_iv_mode, type_iv_hash,
	    name_cipher, name_block_mode, name_iv_mode, name_iv_hash);
}

void
check_spec(ssize_t sz_key,
    enum cipher_type type_cipher, enum block_mode type_block_mode,
    enum iv_mode type_iv_mode, enum hash_type type_iv_hash,
    const std::string &name_cipher, const std::string &name_block_mode,
    const std::string &name_iv_mode, const std::string &name_iv_hash)
    throw (Bad_spec)
{
	if (type_cipher == CT_UNDEFINED)
		throw Bad_spec("unrecognized cipher: " + name_cipher);
	if (type_block_mode == BM_UNDEFINED)
		throw Bad_spec("unrecognized block mode: " + name_block_mode);
	if (!name_iv_mode.empty() && type_iv_mode == IM_UNDEFINED)
		throw Bad_spec("unrecognized IV mode: " + name_iv_mode);
	if (!name_iv_hash.empty() && type_iv_hash == HT_UNDEFINED)
		throw Bad_spec("unrecognized IV hash: " + name_iv_hash);

	const Cipher_traits *cipher_traits =
	    Cipher_traits::traits(type_cipher);
	const Hash_traits *ivhash_traits = Hash_traits::traits(type_iv_hash);

	// canonize cipher and IV hash; note that ivhash will remain an
	// empty string if it was empty initially
	std::string canon_cipher = cipher_traits->name;
	std::string canon_hash = ivhash_traits ?
	    ivhash_traits->name : name_iv_hash;

	// is the cipher spec supported by the system?
	{
		const std::set<std::string> &sys_ciph = system_ciphers();
		if (!sys_ciph.count(canon_cipher))
			throw Bad_spec("cipher not supported by system: " +
			    name_cipher);

		const std::set<std::string> &sys_hash = system_hashes();
		if (name_iv_hash.size() && !sys_hash.count(name_iv_hash))
			throw Bad_spec("IV hash not supported by system: " +
			    name_iv_hash);
	}

	// XXX how to check for CBC, etc?  They get added to /proc/crypto, but
	// XXX only *after* dm-crypt attempts to use them.

	const std::vector<uint16_t> &sizes = cipher_traits->key_sizes;
	if (sz_key == -1)
		// use the largest possible size
		sz_key = sizes.back();
	else if (!std::binary_search(sizes.begin(), sizes.end(), sz_key)) {
		// sz_key not compatible with the cipher
		std::ostringstream out;
		out << "cipher `" << name_cipher
		    << "' only supports keys of sizes";
		for (std::vector<uint16_t>::const_iterator i = sizes.begin();
		    i != sizes.end(); ++i) {
			if (i != sizes.begin()) out << ',';
			out << ' ' << *i * 8;
		}
		out << " (not " << sz_key << ')';
		throw Bad_spec(out.str());
	}

	// are the specs compatible?
	if (type_block_mode == BM_ECB && type_iv_mode != IM_UNDEFINED)
		throw Bad_spec("ECB cannot use an IV mode");
	if (type_block_mode != BM_ECB && type_iv_mode == IM_UNDEFINED)
		throw Bad_spec(
		    "block modes other than ECB require an IV mode");
	if (type_iv_mode == IM_ESSIV && type_iv_hash == HT_UNDEFINED)
		throw Bad_spec("IV mode `essiv' requires an IV hash");
	if (type_iv_mode == IM_PLAIN && type_iv_hash != HT_UNDEFINED)
		throw Bad_spec("IV mode `plain' cannot use an IV hash");
	if (type_iv_mode == IM_ESSIV) {
		// check that ESSIV hash size is a possible key size of the
		// cipher
		uint16_t size = ivhash_traits->digest_size;
		if (!std::binary_search(sizes.begin(), sizes.end(), size)) {
			std::ostringstream out;
			out << "cipher `" << name_cipher
			    << "' only supports keys of sizes";
			for (std::vector<uint16_t>::const_iterator i =
			    sizes.begin(); i != sizes.end(); ++i) {
				if (i != sizes.begin())
					out << ',';
				out << ' ' << (*i * 8);
			}
			out << "; incompatible with hash `" << name_iv_hash
			    << '\'';
			throw Bad_spec(out.str());
		}
	}

}

} // end anon namespace
}

void
fluks::parse_cipher_spec(const std::string &spec, ssize_t sz_key,
    enum cipher_type *out_cipher_type,
    enum block_mode *out_block_mode,
    enum iv_mode *out_iv_mode,
    enum hash_type *out_iv_hash,
    std::string *out_canonical_cipher,
    std::string *out_canonical_mode) throw (Bad_spec)
{
	// valid patterns:
	// [^-]* - [^-*]
	// [^-]* - [^-*] - [^:]*
	// [^-]* - [^-*] - [^:]* : .*
	boost::regex expr(
	    "([^-]+) - ([^-]+)  (?: - ([^:]+) )?  (?: : (.+) )?",
	    boost::regex_constants::normal |
	    boost::regex_constants::mod_x); // ignore space

	boost::smatch matches;
	if (!boost::regex_match(spec, matches, expr))
		throw Bad_spec("cannot be parsed");

	std::string name_cipher = matches[1];
	std::string name_block_mode = matches[2];
	std::string name_iv_mode = matches[3];
	std::string name_iv_hash = matches[4];

	enum cipher_type	type_cipher =
	    Cipher_traits::type(name_cipher);
	enum block_mode		type_block_mode =
	    block_mode_info::type(name_block_mode);
	enum iv_mode		type_iv_mode =
	    iv_mode_info::type(name_iv_mode);
	enum hash_type		type_iv_hash =
	    Hash_traits::type(name_iv_hash);

	check_spec(sz_key,
	    type_cipher, type_block_mode, type_iv_mode, type_iv_hash,
	    name_cipher, name_block_mode, name_iv_mode, name_iv_hash);

	const Cipher_traits *cipher_traits =
	    Cipher_traits::traits(type_cipher);
	std::string canon_cipher = cipher_traits->name;

	*out_cipher_type = type_cipher;
	*out_block_mode = type_block_mode;
	*out_iv_mode = type_iv_mode;
	*out_iv_hash = type_iv_hash;
	if (out_canonical_cipher) *out_canonical_cipher = canon_cipher;
	if (out_canonical_mode) {
		// recreate a canonical cipher spec; note
		// that cipher and ivhash were already canonized
		std::string mode = make_mode(name_block_mode, name_iv_mode,
		    name_iv_hash);
		*out_canonical_mode = mode;
	}
}

fluks::Crypter::Crypter(const uint8_t *key, ssize_t sz_key,
    const std::string &cipher_spec) throw (Bad_spec) :
	_key(new uint8_t[sz_key]),
	_cipher(),
	_iv_hash(),
	_sz_key(sz_key),
	_cipher_type(CT_UNDEFINED),
	_block_mode(BM_UNDEFINED),
	_iv_mode(IM_UNDEFINED)
{
	enum hash_type		hash;

	parse_cipher_spec(cipher_spec, sz_key,
	    &_cipher_type, &_block_mode, &_iv_mode, &hash, 0, 0);
	std::copy(key, key + sz_key, _key.get());

	_cipher = Cipher::create(_cipher_type);
	_cipher->init(_key.get(), _sz_key);
	if (hash != HT_UNDEFINED)
		_iv_hash = Hash_function::create(hash);
}

fluks::Crypter::Crypter(const uint8_t *key, ssize_t sz_key,
    enum cipher_type cipher,
    enum block_mode block_mode,
    enum iv_mode iv_mode,
    enum hash_type iv_hash) throw (Bad_spec) :
	_key(new uint8_t[sz_key]),
	_sz_key(sz_key),
	_cipher_type(cipher),
	_block_mode(block_mode),
	_iv_mode(iv_mode)
{
	check_spec(sz_key, _cipher_type, _block_mode, _iv_mode, iv_hash);
	std::copy(key, key + sz_key, _key.get());

	_cipher = Cipher::create(_cipher_type);
	_cipher->init(_key.get(), _sz_key);
	if (iv_hash != HT_UNDEFINED)
		_iv_hash = Hash_function::create(iv_hash);
}

size_t
fluks::Crypter::ciphertext_size(size_t sz_data) const
{
	switch (_block_mode) {
	case BM_CBC:
	case BM_ECB:
	case BM_PCBC: {
		size_t blocksize = _cipher->traits()->block_size;
		size_t numblocks = (sz_data + blocksize - 1) / blocksize;
		return numblocks * blocksize;
	}
	case BM_CFB:
	case BM_CTR:
	case BM_OFB:
		return sz_data;
	default:
		Assert(0, "ciphertext_size() block mode undefined");
		return 0;
	}
}

void
fluks::Crypter::encrypt(uint32_t start_sector, size_t sz_sector,
    const uint8_t *data, size_t sz_data, uint8_t *out)
{
	std::tr1::shared_ptr<Cipher> iv_crypt;
	boost::scoped_array<uint32_t> pre_essiv32;
	uint32_t	iv32[_cipher->traits()->block_size / 4];

	uint8_t		*iv = reinterpret_cast<uint8_t *>(iv32);
	uint8_t 	*pre_essiv = 0;
	size_t		sz_blk = _cipher->traits()->block_size;
	uint16_t	num_sect = (sz_data + sz_sector - 1) / sz_sector;

	switch (_iv_mode) {
	case IM_PLAIN:
	case IM_UNDEFINED:
		std::fill(iv, iv + sz_blk, 0);
		break;
	case IM_ESSIV:
		iv_crypt = make_essiv_cipher(_cipher_type, _iv_hash.get(),
		    _key.get(), _sz_key);
		pre_essiv32.reset(new uint32_t[sz_blk / 4]);
		pre_essiv = reinterpret_cast<uint8_t *>(pre_essiv32.get());
		std::fill(pre_essiv, pre_essiv + sz_blk, 0);
		break;
	}

	crypt_fn encrypt_fn = get_encrypt_fn();

	Assert(sz_sector % sz_blk == 0,
	    "sector size must be a multiple of the cipher's block size");
	for (uint16_t s = 0; s < num_sect; s++) {
		// generate a new IV for this sector
		switch (_iv_mode) {
		case IM_PLAIN:
			iv32[0] = htole32(start_sector + s);
			break;
		case IM_ESSIV:
			pre_essiv32.get()[0] = htole32(start_sector + s);
			iv_crypt->encrypt(pre_essiv, iv);
			break;
		case IM_UNDEFINED:
			// IV never changes
			break;
		}

		uint16_t by;
		if (s == num_sect - 1) {
			by = sz_data - sz_sector * (num_sect - 1);
		} else {
			by = sz_sector;
		}

		encrypt_fn(_cipher.get(), iv, data, by, out);

		data += sz_sector;
		out += sz_sector;
	}
}

void
fluks::Crypter::decrypt(uint32_t start_sector, size_t sz_sector,
    const uint8_t *data, size_t sz_data, uint8_t *out)
{
	std::tr1::shared_ptr<Cipher> iv_crypt;
	boost::scoped_array<uint32_t> pre_essiv32;
	uint32_t	iv32[_cipher->traits()->block_size / 4];

	uint8_t		*iv = reinterpret_cast<uint8_t *>(iv32);
	uint8_t		*pre_essiv = 0;
	size_t		sz_blk = _cipher->traits()->block_size;
	uint16_t	num_sect = (sz_data + sz_sector - 1) / sz_sector;

	switch (_iv_mode) {
	case IM_PLAIN:
	case IM_UNDEFINED:
		std::fill(iv, iv + sz_blk, 0);
		break;
	case IM_ESSIV:
		iv_crypt = make_essiv_cipher(_cipher_type, _iv_hash.get(),
		    _key.get(), _sz_key);
		pre_essiv32.reset(new uint32_t[sz_blk / 4]);
		pre_essiv = reinterpret_cast<uint8_t *>(pre_essiv32.get());
		std::fill(pre_essiv, pre_essiv + sz_blk, 0);
		break;
	}

	crypt_fn decrypt_fn = get_decrypt_fn();

	Assert(sz_sector % sz_blk == 0,
	    "sector size must be a multiple of the cipher's block size");
	for (uint16_t s = 0; s < num_sect; s++) {
		// generate a new IV for this sector
		switch (_iv_mode) {
		case IM_PLAIN:
			iv32[0] = htole32(start_sector + s);
			break;
		case IM_ESSIV:
			pre_essiv32.get()[0] = htole32(start_sector + s);
			iv_crypt->encrypt(pre_essiv, iv);
			break;
		case IM_UNDEFINED:
			// IV does not change
			break;
		}

		uint16_t by;
		if (s == num_sect - 1) {
			by = sz_data - sz_sector * (num_sect - 1);
		} else {
			by = sz_sector;
		}

		decrypt_fn(_cipher.get(), iv, data, by, out);

		data += sz_sector;
		out += sz_sector;
	}
}

fluks::Crypter::crypt_fn
fluks::Crypter::get_encrypt_fn() const
{
	switch (_block_mode) {
	case BM_CBC:	return cbc_encrypt;
	case BM_CFB:	return cfb_encrypt;
	case BM_CTR:	return ctr_encrypt;
	case BM_ECB:	return ecb_encrypt;
	case BM_OFB:	return ofb_encrypt;
	case BM_PCBC:	return pcbc_encrypt;
	default:
		Assert(0, "encrypt() block mode undefined");
		return 0;
	}
}

fluks::Crypter::crypt_fn
fluks::Crypter::get_decrypt_fn() const
{
	switch (_block_mode) {
	case BM_CBC:	return cbc_decrypt;
	case BM_CFB:	return cfb_decrypt;
	case BM_CTR:	return ctr_decrypt;
	case BM_ECB:	return ecb_decrypt;
	case BM_OFB:	return ofb_decrypt;
	case BM_PCBC:	return pcbc_decrypt;
	default:
		Assert(0, "decrypt() block mode undefined");
		return 0;
	}
}

void
fluks::cbc_encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint8_t		buf[cipher->traits()->block_size];
	uint32_t	blocks = sz_plain / cipher->traits()->block_size;
	size_t		sz_blk = cipher->traits()->block_size;

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// first block:
		//   out = E(in XOR iv)
		// for rest:
		//   out = E(in XOR out-prev)
		if (i)
			xor_bufs(out - sz_blk, in, sz_blk, buf);
		else
			xor_bufs(iv, in, sz_blk, buf);
		cipher->encrypt(buf, out);

		in += sz_blk;
		out += sz_blk;
	}

	// encrypt partial block
	uint32_t left = sz_plain % sz_blk;
	if (left) {
		if (blocks)
			// not first block
			xor_bufs(out - sz_blk, in, left, buf);
		else
			// first block
			xor_bufs(iv, in, left, buf);
		std::fill(buf + left, buf + sz_blk, 0);
		cipher->encrypt(buf, out);
	}
}

void
fluks::cbc_decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint8_t		buf[cipher->traits()->block_size];
	uint32_t	blocks = sz_plain / cipher->traits()->block_size;
	size_t		sz_blk = cipher->traits()->block_size;

	// decrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// first block:
		//   out = D(in) XOR iv
		// for rest:
		//   out = D(in) XOR in-prev
		cipher->decrypt(in, out);
		if (i)
			xor_bufs(out, in - sz_blk, sz_blk, out);
		else
			xor_bufs(out, iv, sz_blk, out);

		in += sz_blk;
		out += sz_blk;
	}

	// decrypt partial block
	uint32_t left = sz_plain % sz_blk;
	if (left) {
		cipher->decrypt(in, buf);
		if (blocks)
			// not first block
			xor_bufs(buf, in - sz_blk, left, out);
		else
			// first block
			xor_bufs(buf, iv, left, out);
	}
}

void
fluks::cfb_encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz, uint8_t *out)
{
	uint32_t	blocks = sz / cipher->traits()->block_size;
	size_t		sz_blk = cipher->traits()->block_size;

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// first block:
		//   out = E(IV) XOR in
		// for rest:
		//   out = E(out_prev) XOR in
		if (i)
			cipher->encrypt(out - sz_blk, out);
		else
			cipher->encrypt(iv, out);
		xor_bufs(in, out, sz_blk, out);

		in += sz_blk;
		out += sz_blk;
	}

	// encrypt partial block
	uint32_t left = sz % sz_blk;
	if (left) {
		uint8_t buf[sz_blk];

		if (blocks)
			cipher->encrypt(out - sz_blk, buf);
		else
			cipher->encrypt(iv, buf);
		xor_bufs(in, buf, left, out);
	}
}

void
fluks::cfb_decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz, uint8_t *out)
{
	uint32_t	blocks = sz / cipher->traits()->block_size;
	size_t		sz_blk = cipher->traits()->block_size;

	// decrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// first block:
		//   out = E(IV) XOR in
		// for rest:
		//   out = E(in_prev) XOR in
		if (i)
			cipher->encrypt(in - sz_blk, out);
		else
			cipher->encrypt(iv, out);
		xor_bufs(in, out, sz_blk, out);

		in += sz_blk;
		out += sz_blk;
	}

	// encrypt partial block
	uint32_t left = sz % sz_blk;
	if (left) {
		uint8_t buf[sz_blk];

		if (blocks)
			cipher->encrypt(in - sz_blk, buf);
		else
			cipher->encrypt(iv, buf);
		xor_bufs(in, buf, left, out);
	}
}

void
fluks::ctr_encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz, uint8_t *out)
{
	uint8_t		pre[cipher->traits()->block_size];
	uint32_t	blocks = sz / cipher->traits()->block_size;
	uint32_t	iv_tail;
	size_t		sz_blk = cipher->traits()->block_size;

	// copy all but last 4 bytes from 'iv' to 'pre'
	std::copy(iv, iv + sz_blk - 4, pre);
	// copy last 4 bytes into 'iv_tail'
	iv_tail = be32toh(
	    *reinterpret_cast<const uint32_t *>(iv + sz_blk - 4));

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// in effect, pre = iv XOR counter
		*reinterpret_cast<uint32_t *>(pre + sz_blk - 4) =
		    htobe32(i ^ iv_tail);

		cipher->encrypt(pre, out);
		xor_bufs(out, in, sz_blk, out);

		in += sz_blk;
		out += sz_blk;
	}

	// encrypt partial block
	uint32_t left = sz % sz_blk;
	if (left) {
		uint8_t post[sz_blk];

		*reinterpret_cast<uint32_t *>(pre + sz_blk - 4) =
		    htobe32(blocks ^ iv_tail);

		cipher->encrypt(pre, post);
		xor_bufs(post, in, left, out);
	}
}

void
fluks::ecb_encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint32_t	blocks = sz_plain / cipher->traits()->block_size;
	size_t		sz_blk = cipher->traits()->block_size;

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		cipher->encrypt(in, out);

		in += sz_blk;
		out += sz_blk;
	}

	// encrypt partial block
	uint32_t left = sz_plain % sz_blk;
	if (left) {
		uint8_t buf[sz_blk];
		std::copy(in, in + left, buf);
		std::fill(buf + left, buf + sz_blk, 0);
		cipher->encrypt(buf, out);
	}
}

void
fluks::ecb_decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint32_t	blocks = sz_plain / cipher->traits()->block_size;
	size_t		sz_blk = cipher->traits()->block_size;

	// decrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		cipher->decrypt(in, out);

		in += sz_blk;
		out += sz_blk;
	}

	// decrypt partial block
	uint32_t left = sz_plain % sz_blk;
	if (left) {
		uint8_t buf[sz_blk];
		cipher->decrypt(in, buf);
		std::copy(buf, buf + left, out);
	}
}

void
fluks::ofb_encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz, uint8_t *out)
{
	// need two buffers because cannot encrypt in place
	uint8_t		buf1[cipher->traits()->block_size];
	uint8_t		buf2[cipher->traits()->block_size];
	uint32_t	blocks = sz / cipher->traits()->block_size;
	size_t		sz_blk = cipher->traits()->block_size;
	uint8_t		*buf_this = buf1;
	uint8_t		*buf_prev = buf2;

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// first block:
		//   tmp = E(IV)
		//   out = tmp XOR in
		// for rest:
		//   tmp = E(tmp)
		//   out = tmp XOR in
		if (i)
			cipher->encrypt(buf_prev, buf_this);
		else
			cipher->encrypt(iv, buf_this);
		xor_bufs(in, buf_this, sz_blk, out);

		in += sz_blk;
		out += sz_blk;
		std::swap(buf_this, buf_prev);
	}

	// encrypt partial block
	uint32_t left = sz % sz_blk;
	if (left) {
		if (blocks)
			cipher->encrypt(buf_prev, buf_this);
		else
			cipher->encrypt(iv, buf_this);
		xor_bufs(in, buf_this, left, out);
	}
}

void
fluks::pcbc_encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint8_t		buf[cipher->traits()->block_size];
	uint32_t	blocks = sz_plain / cipher->traits()->block_size;
	size_t		sz_blk = cipher->traits()->block_size;

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// first block:
		//   out = E(in XOR iv)
		// for rest:
		//   out = E(in XOR out-prev XOR in-prev)
		if (i) {
			xor_bufs(out - sz_blk, in - sz_blk, sz_blk, buf);
			xor_bufs(buf, in, sz_blk, buf);
		} else
			xor_bufs(iv, in, sz_blk, buf);
		cipher->encrypt(buf, out);

		in += sz_blk;
		out += sz_blk;
	}

	// encrypt partial block
	uint32_t left = sz_plain % sz_blk;
	if (left) {
		if (sz_plain > sz_blk) {
			// not first block
			xor_bufs(out - sz_blk, in - sz_blk, sz_blk, buf);
			xor_bufs(buf, in, left, buf);
		} else {
			// first block
			xor_bufs(iv, in, left, buf);
			std::copy(iv + left, iv + sz_blk, buf + left);
		}
		cipher->encrypt(buf, out);
	}
}

void
fluks::pcbc_decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint32_t	blocks = sz_plain / cipher->traits()->block_size;
	size_t		sz_blk = cipher->traits()->block_size;

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// first block:
		//   out = D(in) XOR iv
		// for rest:
		//   out = D(in) XOR out-prev XOR in-prev
		cipher->decrypt(in, out);
		if (i) {
			xor_bufs(out - sz_blk, out, sz_blk, out);
			xor_bufs(in - sz_blk, out, sz_blk, out);
		} else
			xor_bufs(iv, out, sz_blk, out);

		in += sz_blk;
		out += sz_blk;
	}

	// encrypt partial block
	uint32_t left = sz_plain % sz_blk;
	if (left) {
		uint8_t buf[sz_blk];
		cipher->decrypt(in, buf);
		if (sz_plain > sz_blk) {
			// not first block
			xor_bufs(out - sz_blk, buf, left, out);
			xor_bufs(in - sz_blk, out, left, out);
		} else {
			// first block
			xor_bufs(iv, buf, left, out);
		}
	}
}

size_t
fluks::ciphertext_size(enum cipher_type cipher, enum block_mode block_mode,
    size_t sz_data)
{
	switch (block_mode) {
	case BM_CBC:
	case BM_ECB:
	case BM_PCBC: {
		size_t blocksize =
		    Cipher_traits::traits(cipher)->block_size;
		size_t numblocks = (sz_data + blocksize - 1) / blocksize;
		return numblocks * blocksize;
	}
	case BM_CFB:
	case BM_CTR:
	case BM_OFB:
		return sz_data;
	default:
		Assert(0, "ciphertext_size() block mode undefined");
		return 0;
	}
}

void
fluks::encrypt(enum cipher_type type, enum block_mode block_mode,
    enum iv_mode iv_mode, enum hash_type iv_hash,
    uint32_t start_sector, size_t sz_sector,
    const uint8_t *key, size_t sz_key,
    const uint8_t *data, size_t sz_data, uint8_t *out)
{
	std::tr1::shared_ptr<Cipher> cipher = Cipher::create(type);
	std::tr1::shared_ptr<Cipher> iv_crypt;
	std::tr1::shared_ptr<Hash_function> iv_hashfn;
	boost::scoped_array<uint32_t> pre_essiv32;
	uint32_t	iv32[cipher->traits()->block_size / 4];

	uint8_t		*iv = reinterpret_cast<uint8_t *>(iv32);
	uint8_t 	*pre_essiv = 0;
	size_t		sz_blk = cipher->traits()->block_size;
	uint16_t	num_sect = (sz_data + sz_sector - 1) / sz_sector;

	cipher->init(key, sz_key);

	switch (iv_mode) {
	case IM_PLAIN:
	case IM_UNDEFINED:
		std::fill(iv, iv + sz_blk, 0);
		break;
	case IM_ESSIV:
		iv_hashfn = Hash_function::create(iv_hash);
		iv_crypt = make_essiv_cipher(type, iv_hashfn.get(),
		    key, sz_key);
		pre_essiv32.reset(new uint32_t[sz_blk / 4]);
		pre_essiv = reinterpret_cast<uint8_t *>(pre_essiv32.get());
		std::fill(pre_essiv, pre_essiv + sz_blk, 0);
		break;
	}

	void (*encrypt)(Cipher *, const uint8_t *, const uint8_t *, size_t,
	    uint8_t *);
	switch (block_mode) {
	case BM_CBC:
		encrypt = cbc_encrypt;
		break;
	case BM_CFB:
		encrypt = cfb_encrypt;
		break;
	case BM_CTR:
		encrypt = ctr_encrypt;
		break;
	case BM_ECB:
		encrypt = ecb_encrypt;
		break;
	case BM_OFB:
		encrypt = ofb_encrypt;
		break;
	case BM_PCBC:
		encrypt = pcbc_encrypt;
		break;
	default:
		Assert(0, "encrypt() block mode undefined");
		return;
	}

	Assert(sz_sector % sz_blk == 0,
	    "sector size must be a multiple of the cipher's block size");
	for (uint16_t s = 0; s < num_sect; s++) {
		// generate a new IV for this sector
		switch (iv_mode) {
		case IM_PLAIN:
			iv32[0] = htole32(start_sector + s);
			break;
		case IM_ESSIV:
			pre_essiv32.get()[0] = htole32(start_sector + s);
			iv_crypt->encrypt(pre_essiv, iv);
			break;
		case IM_UNDEFINED:
			// IV never changes
			break;
		}

		uint16_t by;
		if (s == num_sect - 1) {
			by = sz_data - sz_sector * (num_sect - 1);
		} else {
			by = sz_sector;
		}

		encrypt(cipher.get(), iv, data, by, out);

		data += sz_sector;
		out += sz_sector;
	}
}

void
fluks::decrypt(enum cipher_type type, enum block_mode block_mode,
    enum iv_mode iv_mode, enum hash_type iv_hash,
    uint32_t start_sector, size_t sz_sector,
    const uint8_t *key, size_t sz_key,
    const uint8_t *data, size_t sz_data, uint8_t *out)
{
	std::tr1::shared_ptr<Cipher> cipher = Cipher::create(type);
	std::tr1::shared_ptr<Cipher> iv_crypt;
	std::tr1::shared_ptr<Hash_function> iv_hashfn;
	boost::scoped_array<uint32_t> pre_essiv32;
	uint32_t	iv32[cipher->traits()->block_size / 4];

	uint8_t		*iv = reinterpret_cast<uint8_t *>(iv32);
	uint8_t		*pre_essiv = 0;
	size_t		sz_blk = cipher->traits()->block_size;
	uint16_t	num_sect = (sz_data + sz_sector - 1) / sz_sector;

	cipher->init(key, sz_key);

	switch (iv_mode) {
	case IM_PLAIN:
	case IM_UNDEFINED:
		std::fill(iv, iv + sz_blk, 0);
		break;
	case IM_ESSIV:
		iv_hashfn = Hash_function::create(iv_hash);
		iv_crypt = make_essiv_cipher(type, iv_hashfn.get(),
		    key, sz_key);
		pre_essiv32.reset(new uint32_t[sz_blk / 4]);
		pre_essiv = reinterpret_cast<uint8_t *>(pre_essiv32.get());
		std::fill(pre_essiv, pre_essiv + sz_blk, 0);
		break;
	}

	void (*decrypt)(Cipher *, const uint8_t *, const uint8_t *, size_t,
	    uint8_t *);
	switch (block_mode) {
	case BM_CBC:
		decrypt = cbc_decrypt;
		break;
	case BM_CFB:
		decrypt = cfb_decrypt;
		break;
	case BM_CTR:
		decrypt = ctr_decrypt;
		break;
	case BM_ECB:
		decrypt = ecb_decrypt;
		break;
	case BM_OFB:
		decrypt = ofb_decrypt;
		break;
	case BM_PCBC:
		decrypt = pcbc_decrypt;
		break;
	default:
		Assert(0, "decrypt() block mode undefined");
		return;
	}

	Assert(sz_sector % sz_blk == 0,
	    "sector size must be a multiple of the cipher's block size");
	for (uint16_t s = 0; s < num_sect; s++) {
		// generate a new IV for this sector
		switch (iv_mode) {
		case IM_PLAIN:
			iv32[0] = htole32(start_sector + s);
			break;
		case IM_ESSIV:
			pre_essiv32.get()[0] = htole32(start_sector + s);
			iv_crypt->encrypt(pre_essiv, iv);
			break;
		case IM_UNDEFINED:
			// IV does not change
			break;
		}

		uint16_t by;
		if (s == num_sect - 1) {
			by = sz_data - sz_sector * (num_sect - 1);
		} else {
			by = sz_sector;
		}

		decrypt(cipher.get(), iv, data, by, out);

		data += sz_sector;
		out += sz_sector;
	}
}
