#include <arpa/inet.h>

#include <stdint.h>

#include <algorithm>
#include <cstddef>

#include "crypt.hpp"
#include "hash.hpp"
#include "util.hpp"

namespace luks {
namespace {

inline void	derive_essiv(Crypt *crypter, uint32_t sector,
		    uint8_t *sector_buf, uint8_t *essiv);

inline void
derive_essiv(Crypt *crypter, uint32_t sector,
    uint8_t *sector_buf, uint8_t *essiv)
{
	// sector number needs to be le64
	reinterpret_cast<uint32_t *>(sector_buf)[0] = host_little(sector);
	reinterpret_cast<uint32_t *>(sector_buf)[1] = 0;
	crypter->crypt(sector_buf, essiv);
}

} // end anon namespace
}

std::tr1::shared_ptr<luks::Crypt> 
luks::Crypt::create(enum cipher_type type)
{
	switch (type) {
	case CT_AES:
		return std::tr1::shared_ptr<Crypt>(new Crypt_aes);
/*
	case CT_BLOWFISH:
	case CT_DES3:
	case CT_TWOFISH:
	case CT_SERPENT:
*/
	default:
		return std::tr1::shared_ptr<Crypt>();
	}
}

void
luks::cbc_encrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint8_t		buf[crypter->block_size()];
	uint32_t	blocks = sz_plain / crypter->block_size();
	size_t		sz_blk = crypter->block_size();

	// encypt whole blocks
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
luks::cbc_decrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
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
luks::ctr_encrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz, uint8_t *out)
{
	uint8_t		pre[crypter->block_size()];
	uint8_t		post[crypter->block_size()];
	uint32_t	blocks = sz / crypter->block_size();
	uint32_t	iv_tail;
	size_t		sz_blk = crypter->block_size();

	// copy all but last 4 bytes from 'iv' to 'pre'
	std::copy(iv, iv + sz_blk - 4, pre);
	// copy last 4 bytes into 'iv_tail'
	iv_tail = ntohl(*reinterpret_cast<const uint32_t *>(iv + sz_blk - 4));

	// encrypt whole blocks
	for (uint32_t i = 0; i < blocks; i++) {
		// pre = iv XOR counter
		*reinterpret_cast<uint32_t *>(pre + sz_blk - 4) =
		    htonl(i ^ iv_tail);

		crypter->crypt(pre, post);
		xor_bufs(post, in, sz_blk, out);

		in += sz_blk;
		out += sz_blk;
	}

	// encrypt partial block
	uint32_t left = sz % sz_blk;
	if (left) {
		// pre = iv XOR counter
		*reinterpret_cast<uint32_t *>(pre + sz_blk - 4) =
		    htonl(blocks ^ iv_tail);

		crypter->crypt(pre, post);
		xor_bufs(post, in, left, out);
	}
}

void
luks::cts_encrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	uint8_t		buf[crypter->block_size()];
	size_t		sz_blk = crypter->block_size();

	if (sz_plain <= sz_blk) {
		// this situation is completely undefined by RFC 2040; the
		// most reasonable solution I can think of is to call the
		// only block P_{n-1} and the following block of length 0 P_n;
		// then:
		//	X_{n-1} = IV ^ P_{n-1}
		//	E_{n-1} = E(X_{n-1})
		//	C_{n-1} = E(E_{n-1})
		// or
		//	out = E(E(IV ^ in))
		// but then what's the point of encrypting twice? instead,
		// I pad the block and encrypt it CBC style
		xor_bufs(iv, in, sz_plain, buf);
		std::copy(iv + sz_plain, iv + sz_blk, buf + sz_plain);
		crypter->crypt(buf, out);
	} else if (sz_plain <= sz_blk * 2) {
		uint8_t buf2[crypter->block_size()];
		uint32_t remainder = sz_plain % sz_blk;
		xor_bufs(iv, in, sz_blk, buf);
		crypter->crypt(buf, buf2);
		std::copy(buf2, buf2 + remainder, out + sz_blk);
		xor_bufs(in + sz_blk, buf2, remainder, buf2);
		crypter->crypt(buf2, out);
	} else {
		// TODO
	}
}

void
luks::cts_decrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz_plain, uint8_t *out)
{
	// TODO
}

void
luks::ecb_encrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
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
luks::ecb_decrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
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
