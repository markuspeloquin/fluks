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

#include <algorithm>
#include <functional>
#include <set>
#include <sstream>
#include <tr1/cstdint>
#include <boost/regex.hpp>

#include "cipher.hpp"
#include "cipher_spec.hpp"
#include "crypt.hpp"
#include "detect.hpp"
#include "errors.hpp"
#include "hash.hpp"
#include "util.hpp"

namespace fluks {
namespace {

inline std::tr1::shared_ptr<Cipher>
		make_essiv_cipher(enum cipher_type, Hash_function *,
		    const uint8_t *key, size_t sz);

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

} // end anon namespace
}

fluks::Crypter::Crypter(const uint8_t *key, size_t sz_key,
    const Cipher_spec &spec) :
	_key(new uint8_t[sz_key]),
	_cipher(Cipher::create(spec.type_cipher())),
	_spec(spec),
	_sz_key(sz_key)
{
	std::copy(key, key + sz_key, _key.get());
	_cipher->init(_key.get(), _sz_key);
	if (_spec.type_iv_hash() != HT_UNDEFINED)
		_iv_hash = Hash_function::create(_spec.type_iv_hash());
}

fluks::Crypter::Crypter(const Crypter &rhs) :
	_key(const_cast<Crypter &>(rhs)._key),
	_cipher(const_cast<Crypter &>(rhs)._cipher),
	_iv_hash(const_cast<Crypter &>(rhs)._iv_hash),
	_spec(rhs._spec),
	_sz_key(rhs._sz_key)
{
}

fluks::Crypter &
fluks::Crypter::operator=(const Crypter &rhs_)
{
	Crypter &rhs = const_cast<Crypter &>(rhs_);

	_key = rhs._key;
	_cipher = rhs._cipher;
	_iv_hash = rhs._iv_hash;
	_spec = rhs._spec;
	_sz_key = rhs._sz_key;

	return *this;
}

std::tr1::shared_ptr<fluks::Crypter>
fluks::Crypter::create(const uint8_t *key, size_t sz_key,
    const Cipher_spec &spec)
{
	switch (spec.type_block_mode()) {
	case BM_CBC:
		return std::tr1::shared_ptr<Crypter>(new Crypter_cbc(
		    key, sz_key, spec));
	case BM_CBC_CTS:
		return std::tr1::shared_ptr<Crypter>(new Crypter_cbc_cts(
		    key, sz_key, spec));
	case BM_CFB:
		return std::tr1::shared_ptr<Crypter>(new Crypter_cfb(
		    key, sz_key, spec));
	case BM_CTR:
		return std::tr1::shared_ptr<Crypter>(new Crypter_ctr(
		    key, sz_key, spec));
	case BM_ECB:
		return std::tr1::shared_ptr<Crypter>(new Crypter_ecb(
		    key, sz_key, spec));
	case BM_OFB:
		return std::tr1::shared_ptr<Crypter>(new Crypter_ofb(
		    key, sz_key, spec));
	case BM_PCBC:
		return std::tr1::shared_ptr<Crypter>(new Crypter_pcbc(
		    key, sz_key, spec));
	default:
		Assert(0, "Crypter::create() bad block mode");
		return std::tr1::shared_ptr<Crypter>();
	}
}

size_t
fluks::Crypter::ciphertext_size_ceil(size_t sz_plaintext) const
{
	size_t blocksize = _cipher->traits()->block_size;
	size_t numblocks = (sz_plaintext + blocksize - 1) / blocksize;
	return numblocks * blocksize;
}

void
fluks::Crypter::encrypt(uint32_t start_sector, size_t sz_sector,
    const uint8_t *data, size_t sz_data, uint8_t *out) throw (Crypt_error)
{
	std::tr1::shared_ptr<Cipher> iv_crypt;
	boost::scoped_array<uint32_t> pre_essiv32;
	uint32_t	iv32[_cipher->traits()->block_size / 4];

	uint8_t		*iv = reinterpret_cast<uint8_t *>(iv32);
	uint8_t		*pre_essiv = 0;
	size_t		sz_blk = _cipher->traits()->block_size;
	uint16_t	num_sect = (sz_data + sz_sector - 1) / sz_sector;

	switch (_spec.type_iv_mode()) {
	case IM_PLAIN:
	case IM_UNDEFINED:
		std::fill(iv, iv + sz_blk, 0);
		break;
	case IM_ESSIV:
		iv_crypt = make_essiv_cipher(_spec.type_cipher(),
		    _iv_hash.get(), _key.get(), _sz_key);
		pre_essiv32.reset(new uint32_t[sz_blk / 4]);
		pre_essiv = reinterpret_cast<uint8_t *>(pre_essiv32.get());
		std::fill(pre_essiv, pre_essiv + sz_blk, 0);
		break;
	}

	Assert(sz_sector % sz_blk == 0,
	    "sector size must be a multiple of the cipher's block size");
	for (uint16_t s = 0; s < num_sect; s++) {
		// generate a new IV for this sector
		switch (_spec.type_iv_mode()) {
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

		encrypt(_cipher.get(), iv, data, by, out);

		data += sz_sector;
		out += sz_sector;
	}
}

void
fluks::Crypter::decrypt(uint32_t start_sector, size_t sz_sector,
    const uint8_t *data, size_t sz_data, uint8_t *out) throw (Crypt_error)
{
	std::tr1::shared_ptr<Cipher> iv_crypt;
	boost::scoped_array<uint32_t> pre_essiv32;
	uint32_t	iv32[_cipher->traits()->block_size / 4];

	uint8_t		*iv = reinterpret_cast<uint8_t *>(iv32);
	uint8_t		*pre_essiv = 0;
	size_t		sz_blk = _cipher->traits()->block_size;
	uint16_t	num_sect = (sz_data + sz_sector - 1) / sz_sector;

	switch (_spec.type_iv_mode()) {
	case IM_PLAIN:
	case IM_UNDEFINED:
		std::fill(iv, iv + sz_blk, 0);
		break;
	case IM_ESSIV:
		iv_crypt = make_essiv_cipher(_spec.type_cipher(),
		    _iv_hash.get(), _key.get(), _sz_key);
		pre_essiv32.reset(new uint32_t[sz_blk / 4]);
		pre_essiv = reinterpret_cast<uint8_t *>(pre_essiv32.get());
		std::fill(pre_essiv, pre_essiv + sz_blk, 0);
		break;
	}

	Assert(sz_sector % sz_blk == 0,
	    "sector size must be a multiple of the cipher's block size");
	for (uint16_t s = 0; s < num_sect; s++) {
		// generate a new IV for this sector
		switch (_spec.type_iv_mode()) {
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

		decrypt(_cipher.get(), iv, data, by, out);

		data += sz_sector;
		out += sz_sector;
	}
}

void
fluks::Crypter_cbc::encrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz_plain, uint8_t *out) throw ()
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
fluks::Crypter_cbc::decrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz_plain, uint8_t *out) throw ()
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
fluks::Crypter_cbc_cts::encrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz, uint8_t *out) throw (Crypt_error)
{
	Assert(0, "not implemented yet");
	uint8_t		buf[cipher->traits()->block_size];
	uint32_t	blocks = sz / cipher->traits()->block_size;
	size_t		sz_blk = cipher->traits()->block_size;

	if (sz < sz_blk) {
		std::ostringstream out;
		out << "CBC-CTS requires at least one block of data ("
		    << sz_blk << " bytes for this cipher)";
		throw Crypt_error(out.str());
	}

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
	uint32_t left = sz % sz_blk;
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
fluks::Crypter_cbc_cts::decrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz, uint8_t *out) throw (Crypt_error)
{
	Assert(0, "not implemented yet");
	uint8_t		buf[cipher->traits()->block_size];
	uint32_t	blocks = sz / cipher->traits()->block_size;
	size_t		sz_blk = cipher->traits()->block_size;

	if (sz < sz_blk) {
		std::ostringstream out;
		out << "CBC-CTS requires at least one block of data ("
		    << sz_blk << " bytes for this cipher)";
		throw Crypt_error(out.str());
	}

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
	uint32_t left = sz % sz_blk;
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
fluks::Crypter_cfb::encrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz, uint8_t *out) throw ()
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
fluks::Crypter_cfb::decrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz, uint8_t *out) throw ()
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
fluks::Crypter_ctr::encrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz, uint8_t *out) throw ()
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
fluks::Crypter_ecb::encrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz_plain, uint8_t *out) throw ()
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
fluks::Crypter_ecb::decrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz_plain, uint8_t *out) throw ()
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
fluks::Crypter_ofb::encrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz, uint8_t *out) throw ()
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
fluks::Crypter_pcbc::encrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz_plain, uint8_t *out) throw ()
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
fluks::Crypter_pcbc::decrypt(Cipher *cipher, const uint8_t *iv,
    const uint8_t *in, size_t sz_plain, uint8_t *out) throw ()
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
