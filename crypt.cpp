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

#include <arpa/inet.h>

#include <stdint.h>

#include <algorithm>
#include <cstddef>
#include <functional>
#include <map>

#include "crypt.hpp"
#include "errors.hpp"
#include "hash.hpp"
#include "util.hpp"

namespace fluks {
namespace {

class Lookup {
public:
	static const Cipher_info *info(enum cipher_type type);
	static enum cipher_type type(const std::string &name);
	static const std::vector<enum cipher_type> &types()
	{	return inst._types; }
private:
	Lookup();
	Lookup(const Lookup &) {}
	void operator=(const Lookup &) {}

	static Lookup inst;
	std::map<enum cipher_type, Cipher_info> _map_info;
	std::map<std::string, enum cipher_type> _map_type;
	std::vector<enum cipher_type> _types;
};

const Cipher_info *
Lookup::info(enum cipher_type type)
{
	std::map<enum cipher_type, Cipher_info>::iterator i;
	i = inst._map_info.find(type);
	if (i == inst._map_info.end()) return 0;
	return &i->second;
}

enum cipher_type
Lookup::type(const std::string &name)
{
	std::map<std::string, enum cipher_type>::iterator i;
	i = inst._map_type.find(name);
	if (i == inst._map_type.end()) return CT_UNDEFINED;
	return i->second;
}

Lookup::Lookup()
{
	_map_info[CT_AES] = Cipher_info("aes", 16, 32, 8, 16, 1);
	_map_info[CT_BLOWFISH] = Cipher_info("blowfish", 4, 56, 1, 8, 0);
	_map_info[CT_CAST5] = Cipher_info("cast5", 5, 16, 1, 8, 1);
	_map_info[CT_CAST6] = Cipher_info("cast6", 16, 32, 4, 16, 1);
	_map_info[CT_SERPENT] = Cipher_info("serpent", 16, 32, 8, 16, 1);
	_map_info[CT_TWOFISH] = Cipher_info("twofish", 16, 32, 8, 16, 1);

	_map_type["aes"] = CT_AES;
	_map_type["blowfish"] = CT_BLOWFISH;
	_map_type["cast5"] = CT_CAST5;
	_map_type["cast6"] = CT_CAST6;
	_map_type["serpent"] = CT_SERPENT;
	_map_type["twofish"] = CT_TWOFISH;

	for (std::map<enum cipher_type, Cipher_info>::iterator i =
	    _map_info.begin(); i != _map_info.end(); ++i)
		_types.push_back(i->first);
}

Lookup Lookup::inst;

inline std::tr1::shared_ptr<Cipher>
		make_essiv_cipher(enum cipher_type cipher,
		    enum hash_type hash, const uint8_t *key, size_t sz);

inline std::tr1::shared_ptr<Cipher>
make_essiv_cipher(enum cipher_type type, enum hash_type hash,
    const uint8_t *key, size_t sz)
{
	std::tr1::shared_ptr<Cipher> cipher(Cipher::create(type));
	std::tr1::shared_ptr<Hash_function> hashfn(
	    Hash_function::create(hash));
	size_t sz_hash = hashfn->digest_size();
	uint8_t key_hash[sz_hash];

	// compute H(K)
	hashfn->init();
	hashfn->add(key, sz);
	hashfn->end(key_hash);

	// set key to H(K)
	cipher->init(key_hash, sz_hash);
	return cipher;
}

} // end anon namespace
}

fluks::Cipher_info::Cipher_info(const std::string &name,
    uint16_t min_key, uint16_t max_key, uint16_t key_step,
    uint16_t sz_blk, uint16_t version) :
	name(name),
	key_sizes((max_key - min_key + (key_step - 1)) / key_step),
	block_size(sz_blk),
	luks_version(version)
{
	size_t i = 0;
	for (uint16_t n = min_key; n <= max_key; n += key_step)
		key_sizes[i++] = n;
}

const fluks::Cipher_info *
fluks::Cipher_info::info(enum cipher_type type)
{
	return Lookup::info(type);
}

enum fluks::cipher_type
fluks::Cipher_info::type(const std::string &name)
{
	return Lookup::type(name);
}

const std::vector<enum fluks::cipher_type> &
fluks::Cipher_info::types()
{
	return Lookup::types();
}

std::tr1::shared_ptr<fluks::Cipher> 
fluks::Cipher::create(enum cipher_type type)
{
	switch (type) {
	case CT_AES:
		return std::tr1::shared_ptr<Cipher>(new Cipher_aes);
	case CT_BLOWFISH:
		return std::tr1::shared_ptr<Cipher>(new Cipher_blowfish);
	case CT_CAST5:
		return std::tr1::shared_ptr<Cipher>(new Cipher_cast5);
	case CT_CAST6:
		return std::tr1::shared_ptr<Cipher>(new Cipher_cast6);
	case CT_SERPENT:
		return std::tr1::shared_ptr<Cipher>(new Cipher_serpent);
	case CT_TWOFISH:
		return std::tr1::shared_ptr<Cipher>(new Cipher_twofish);
/*
	case CT_DES3:
		return std::tr1::shared_ptr<Cipher>(new Cipher_des3);
*/
	default:
		Assert(0, "Cipher::create() bad cipher type");
		return std::tr1::shared_ptr<Cipher>();
	}
}

fluks::Cipher::Cipher(enum cipher_type type)
{
}

void
fluks::cbc_encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint8_t		buf[cipher->info().block_size];
	uint32_t	blocks = sz_plain / cipher->info().block_size;
	size_t		sz_blk = cipher->info().block_size;

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
	uint8_t		buf[cipher->info().block_size];
	uint32_t	blocks = sz_plain / cipher->info().block_size;
	size_t		sz_blk = cipher->info().block_size;

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
	uint32_t	blocks = sz / cipher->info().block_size;
	size_t		sz_blk = cipher->info().block_size;

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
		uint8_t buf[cipher->info().block_size];

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
	uint32_t	blocks = sz / cipher->info().block_size;
	size_t		sz_blk = cipher->info().block_size;

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
		uint8_t buf[cipher->info().block_size];

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
	uint8_t		pre[cipher->info().block_size];
	uint32_t	blocks = sz / cipher->info().block_size;
	uint32_t	iv_tail;
	size_t		sz_blk = cipher->info().block_size;

	// copy all but last 4 bytes from 'iv' to 'pre'
	std::copy(iv, iv + sz_blk - 4, pre);
	// copy last 4 bytes into 'iv_tail'
	iv_tail = ntohl(*reinterpret_cast<const uint32_t *>(iv + sz_blk - 4));

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// in effect, pre = iv XOR counter
		*reinterpret_cast<uint32_t *>(pre + sz_blk - 4) =
		    htonl(i ^ iv_tail);

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
		    htonl(blocks ^ iv_tail);

		cipher->encrypt(pre, post);
		xor_bufs(post, in, left, out);
	}
}

void
fluks::ecb_encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint32_t	blocks = sz_plain / cipher->info().block_size;
	size_t		sz_blk = cipher->info().block_size;

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		cipher->encrypt(in, out);

		in += sz_blk;
		out += sz_blk;
	}

	// encrypt partial block
	uint32_t left = sz_plain % sz_blk;
	if (left) {
		uint8_t buf[cipher->info().block_size];
		std::copy(in, in + left, buf);
		std::fill(buf + left, buf + sz_blk, 0);
		cipher->encrypt(buf, out);
	}
}

void
fluks::ecb_decrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint32_t	blocks = sz_plain / cipher->info().block_size;
	size_t		sz_blk = cipher->info().block_size;

	// decrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		cipher->decrypt(in, out);

		in += sz_blk;
		out += sz_blk;
	}

	// decrypt partial block
	uint32_t left = sz_plain % sz_blk;
	if (left) {
		uint8_t buf[cipher->info().block_size];
		cipher->decrypt(in, buf);
		std::copy(buf, buf + left, out);
	}
}

void
fluks::ofb_encrypt(Cipher *cipher, const uint8_t *iv, const uint8_t *in,
    size_t sz, uint8_t *out)
{
	// need two buffers because cannot encrypt in place
	uint8_t		buf1[cipher->info().block_size];
	uint8_t		buf2[cipher->info().block_size];
	uint32_t	blocks = sz / cipher->info().block_size;
	size_t		sz_blk = cipher->info().block_size;
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
	uint8_t		buf[cipher->info().block_size];
	uint32_t	blocks = sz_plain / cipher->info().block_size;
	size_t		sz_blk = cipher->info().block_size;

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
	uint32_t	blocks = sz_plain / cipher->info().block_size;
	size_t		sz_blk = cipher->info().block_size;

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
		    Cipher_info::info(cipher)->block_size;
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
	std::tr1::shared_ptr<Cipher> cipher(Cipher::create(type));
	std::tr1::shared_ptr<Cipher> iv_crypt;
	boost::scoped_array<uint8_t> pre_essiv;
	uint8_t		iv[cipher->info().block_size];

	size_t		sz_blk = cipher->info().block_size;
	uint16_t	num_sect = (sz_data + sz_sector - 1) / sz_sector;

	cipher->init(key, sz_key);

	switch (iv_mode) {
	case IM_PLAIN:
	case IM_UNDEFINED:
		std::fill(iv, iv + sz_blk, 0);
		break;
	case IM_ESSIV:
		iv_crypt = make_essiv_cipher(type, iv_hash, key, sz_key);
		pre_essiv.reset(new uint8_t[sz_blk]);
		std::fill(pre_essiv.get(), pre_essiv.get() + sz_blk, 0);
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

	for (uint16_t s = 0; s < num_sect; s++) {
		// generate a new IV for this sector
		switch (iv_mode) {
		case IM_PLAIN:
			*reinterpret_cast<uint32_t *>(iv) =
			    host_little(start_sector + s);
			break;
		case IM_ESSIV:
			*reinterpret_cast<uint32_t *>(pre_essiv.get()) =
			    host_little(start_sector + s);
			iv_crypt->encrypt(pre_essiv.get(), iv);
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
	std::tr1::shared_ptr<Cipher> cipher(Cipher::create(type));
	std::tr1::shared_ptr<Cipher> iv_crypt;
	boost::scoped_array<uint8_t> pre_essiv;
	uint8_t		iv[cipher->info().block_size];

	size_t		sz_blk = cipher->info().block_size;
	uint16_t	num_sect = (sz_data + sz_sector - 1) / sz_sector;

	cipher->init(key, sz_key);

	switch (iv_mode) {
	case IM_PLAIN:
	case IM_UNDEFINED:
		std::fill(iv, iv + sz_blk, 0);
		break;
	case IM_ESSIV:
		iv_crypt = make_essiv_cipher(type, iv_hash, key, sz_key);
		pre_essiv.reset(new uint8_t[sz_blk]);
		std::fill(pre_essiv.get(), pre_essiv.get() + sz_blk, 0);
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

	for (uint16_t s = 0; s < num_sect; s++) {
		// generate a new IV for this sector
		switch (iv_mode) {
		case IM_PLAIN:
			*reinterpret_cast<uint32_t *>(iv) =
			    host_little(start_sector + s);
			break;
		case IM_ESSIV:
			*reinterpret_cast<uint32_t *>(pre_essiv.get()) =
			    host_little(start_sector + s);
			iv_crypt->encrypt(pre_essiv.get(), iv);
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
