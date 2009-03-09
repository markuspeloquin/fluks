#include <arpa/inet.h>

#include <stdint.h>

#include <algorithm>
#include <cstddef>

#include "crypt.hpp"
#include "errors.hpp"
#include "hash.hpp"
#include "util.hpp"

namespace fluks {
namespace {

inline std::tr1::shared_ptr<Crypt>
		make_essiv_crypter(enum cipher_type cipher,
		    enum hash_type hash, const uint8_t *key, size_t sz);

inline std::tr1::shared_ptr<Crypt>
make_essiv_crypter(enum cipher_type cipher, enum hash_type hash,
    const uint8_t *key, size_t sz)
{
	std::tr1::shared_ptr<Crypt> crypter(Crypt::create(cipher));
	std::tr1::shared_ptr<Hash_function> hashfn(
	    Hash_function::create(hash));
	size_t sz_hash = hashfn->digest_size();
	uint8_t key_hash[sz_hash];

	// compute H(K)
	hashfn->init();
	hashfn->add(key, sz);
	hashfn->end(key_hash);

	// set key to H(K)
	crypter->init(DIR_ENCRYPT, key_hash, sz_hash);
	return crypter;
}

} // end anon namespace
}

std::tr1::shared_ptr<fluks::Crypt> 
fluks::Crypt::create(enum cipher_type type)
{
	switch (type) {
	case CT_AES:
		return std::tr1::shared_ptr<Crypt>(new Crypt_aes);
	case CT_BLOWFISH:
		return std::tr1::shared_ptr<Crypt>(new Crypt_blowfish);
	case CT_CAST5:
		return std::tr1::shared_ptr<Crypt>(new Crypt_cast5);
	case CT_SERPENT:
		return std::tr1::shared_ptr<Crypt>(new Crypt_serpent);
	case CT_TWOFISH:
		return std::tr1::shared_ptr<Crypt>(new Crypt_twofish);
/*
	case CT_CAST6:
		return std::tr1::shared_ptr<Crypt>(new Crypt_cast6);
	case CT_DES3:
		return std::tr1::shared_ptr<Crypt>(new Crypt_des3);
*/
	default:
		Assert(0, "Crypt::create() bad cipher type");
		return std::tr1::shared_ptr<Crypt>();
	}
}

void
fluks::cbc_encrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint8_t		buf[crypter->block_size()];
	uint32_t	blocks = sz_plain / crypter->block_size();
	size_t		sz_blk = crypter->block_size();

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
		crypter->crypt(buf, out);

		in += sz_blk;
		out += sz_blk;
	}

	// encrypt partial block
	uint32_t left = sz_plain % sz_blk;
	if (left) {
		// write partial block into 'buf'
		std::copy(in, in + left, buf);
		std::fill(buf + left, buf + sz_blk, 0);

		if (sz_plain > sz_blk)
			// not first block
			xor_bufs(out - sz_blk, buf, sz_blk, buf);
		else
			// first block
			xor_bufs(iv, buf, sz_blk, buf);
		crypter->crypt(buf, out);
	}
}

void
fluks::cbc_decrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint8_t		buf[crypter->block_size()];
	uint32_t	blocks = sz_plain / crypter->block_size();
	size_t		sz_blk = crypter->block_size();

	// decrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// first block:
		//   out = D(in) XOR iv
		// for rest:
		//   out = D(in) XOR in-prev
		crypter->crypt(in, out);
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
		crypter->crypt(in, buf);
		if (sz_plain > sz_blk)
			// not first block
			xor_bufs(buf, in - sz_blk, left, out);
		else
			// first block
			xor_bufs(buf, iv, left, out);
	}
}

void
fluks::ctr_encrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz, uint8_t *out)
{
	uint8_t		pre[crypter->block_size()];
	uint32_t	blocks = sz / crypter->block_size();
	uint32_t	iv_tail;
	size_t		sz_blk = crypter->block_size();

	// copy all but last 4 bytes from 'iv' to 'pre'
	std::copy(iv, iv + sz_blk - 4, pre);
	// copy last 4 bytes into 'iv_tail'
	iv_tail = ntohl(*reinterpret_cast<const uint32_t *>(iv + sz_blk - 4));

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// in effect, pre = iv XOR counter
		*reinterpret_cast<uint32_t *>(pre + sz_blk - 4) =
		    htonl(i ^ iv_tail);

		crypter->crypt(pre, out);
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

		crypter->crypt(pre, post);
		xor_bufs(post, in, left, out);
	}
}

void
fluks::ecb_encrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint32_t	blocks = sz_plain / crypter->block_size();
	size_t		sz_blk = crypter->block_size();

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		crypter->crypt(in, out);

		in += sz_blk;
		out += sz_blk;
	}

	// encrypt partial block
	uint32_t left = sz_plain % sz_blk;
	if (left) {
		uint8_t buf[crypter->block_size()];
		std::copy(in, in + left, buf);
		std::fill(buf + left, buf + sz_blk, 0);
		crypter->crypt(buf, out);
	}
}

void
fluks::ecb_decrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint32_t	blocks = sz_plain / crypter->block_size();
	size_t		sz_blk = crypter->block_size();

	// decrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		crypter->crypt(in, out);

		in += sz_blk;
		out += sz_blk;
	}

	// decrypt partial block
	uint32_t left = sz_plain % sz_blk;
	if (left) {
		uint8_t buf[crypter->block_size()];
		crypter->crypt(in, buf);
		std::copy(buf, buf + left, out);
	}
}

void
fluks::pcbc_encrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint8_t		buf[crypter->block_size()];
	uint32_t	blocks = sz_plain / crypter->block_size();
	size_t		sz_blk = crypter->block_size();

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
		crypter->crypt(buf, out);

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
		crypter->crypt(buf, out);
	}
}

void
fluks::pcbc_decrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint32_t	blocks = sz_plain / crypter->block_size();
	size_t		sz_blk = crypter->block_size();

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// first block:
		//   out = D(in) XOR iv
		// for rest:
		//   out = D(in) XOR out-prev XOR in-prev
		crypter->crypt(in, out);
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
		crypter->crypt(in, buf);
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
		size_t blocksize = cipher_info::block_size(cipher);
		size_t numblocks = (sz_data + blocksize - 1) / blocksize;
		return numblocks * blocksize;
	}
	case BM_CTR:
		return sz_data;
	default:
		Assert(0, "ciphertext_size() block mode undefined");
		return 0;
	}
}

void
fluks::encrypt(enum cipher_type cipher, enum block_mode block_mode,
    enum iv_mode iv_mode, enum hash_type iv_hash,
    uint32_t start_sector, size_t sz_sector,
    const uint8_t *key, size_t sz_key,
    const uint8_t *data, size_t sz_data, uint8_t *out)
{
	std::tr1::shared_ptr<Crypt> encrypter(Crypt::create(cipher));
	std::tr1::shared_ptr<Crypt> iv_crypt;
	boost::scoped_array<uint8_t> pre_essiv;
	uint8_t		iv[encrypter->block_size()];

	size_t		sz_blk = encrypter->block_size();
	uint16_t	num_sect = (sz_data + sz_sector - 1) / sz_sector;

	encrypter->init(DIR_ENCRYPT, key, sz_key);

	switch (iv_mode) {
	case IM_PLAIN:
	case IM_UNDEFINED:
		std::fill(iv, iv + sz_blk, 0);
		break;
	case IM_ESSIV:
		iv_crypt = make_essiv_crypter(cipher, iv_hash, key, sz_key);
		pre_essiv.reset(new uint8_t[sz_blk]);
		std::fill(pre_essiv.get(), pre_essiv.get() + sz_blk, 0);
		break;
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
			iv_crypt->crypt(pre_essiv.get(), iv);
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

		switch (block_mode) {
		case BM_CBC:
			cbc_encrypt(encrypter.get(), iv, data, by, out);
			break;
		case BM_CTR:
			ctr_encrypt(encrypter.get(), iv, data, by, out);
			break;
		case BM_ECB:
			ecb_encrypt(encrypter.get(), iv, data, by, out);
			break;
		case BM_PCBC:
			pcbc_encrypt(encrypter.get(), iv, data, by, out);
			break;
		default:
			Assert(0, "encrypt() block mode undefined");
		}

		data += sz_sector;
		out += sz_sector;
	}
}

void
fluks::decrypt(enum cipher_type cipher, enum block_mode block_mode,
    enum iv_mode iv_mode, enum hash_type iv_hash,
    uint32_t start_sector, size_t sz_sector,
    const uint8_t *key, size_t sz_key,
    const uint8_t *data, size_t sz_data, uint8_t *out)
{
	std::tr1::shared_ptr<Crypt> decrypter(Crypt::create(cipher));
	std::tr1::shared_ptr<Crypt> iv_crypt;
	boost::scoped_array<uint8_t> pre_essiv;
	uint8_t		iv[decrypter->block_size()];

	size_t		sz_blk = decrypter->block_size();
	uint16_t	num_sect = (sz_data + sz_sector - 1) / sz_sector;
	enum crypt_direction dir;

	switch (block_mode) {
	case BM_CTR:
		// output feedback and cipher feedback are two others that
		// only require a cipher's encryption algorithm
		dir = DIR_ENCRYPT;
		break;
	default:
		dir = DIR_DECRYPT;
		break;
	}

	decrypter->init(dir, key, sz_key);

	switch (iv_mode) {
	case IM_PLAIN:
	case IM_UNDEFINED:
		std::fill(iv, iv + sz_blk, 0);
		break;
	case IM_ESSIV:
		iv_crypt = make_essiv_crypter(cipher, iv_hash, key, sz_key);
		pre_essiv.reset(new uint8_t[sz_blk]);
		std::fill(pre_essiv.get(), pre_essiv.get() + sz_blk, 0);
		break;
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
			iv_crypt->crypt(pre_essiv.get(), iv);
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

		switch (block_mode) {
		case BM_CBC:
			cbc_decrypt(decrypter.get(), iv, data, by, out);
			break;
		case BM_CTR:
			ctr_decrypt(decrypter.get(), iv, data, by, out);
			break;
		case BM_ECB:
			ecb_decrypt(decrypter.get(), iv, data, by, out);
			break;
		case BM_PCBC:
			pcbc_decrypt(decrypter.get(), iv, data, by, out);
			break;
		default:
			Assert(0, "decrypt() block mode undefined");
		}

		data += sz_sector;
		out += sz_sector;
	}
}
