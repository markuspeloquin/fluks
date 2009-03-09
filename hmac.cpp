#include "hmac.hpp"
#include "util.hpp"

std::tr1::shared_ptr<luks::Hmac_function>
luks::Hmac_function::create(enum hash_type type)
{
	switch (type) {
	case HT_MD5:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_md5);
	case HT_RMD160:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_rmd160);
	case HT_SHA1:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_sha1);
	case HT_SHA224:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_sha224);
	case HT_SHA256:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_sha256);
	case HT_SHA384:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_sha384);
	case HT_SHA512:
		return std::tr1::shared_ptr<Hmac_function>(new Hmac_sha512);
	case HT_TIGER128:
		return std::tr1::shared_ptr<Hmac_function>(
		    new Hmac_impl(Hash_function::create(HT_TIGER128)));
	case HT_TIGER160:
		return std::tr1::shared_ptr<Hmac_function>(
		    new Hmac_impl(Hash_function::create(HT_TIGER160)));
	case HT_TIGER192:
		return std::tr1::shared_ptr<Hmac_function>(
		    new Hmac_impl(Hash_function::create(HT_TIGER192)));
	case HT_WHIRLPOOL256:
		return std::tr1::shared_ptr<Hmac_function>(
		    new Hmac_impl(Hash_function::create(HT_WHIRLPOOL256)));
	case HT_WHIRLPOOL384:
		return std::tr1::shared_ptr<Hmac_function>(
		    new Hmac_impl(Hash_function::create(HT_WHIRLPOOL384)));
	case HT_WHIRLPOOL512:
		return std::tr1::shared_ptr<Hmac_function>(
		    new Hmac_impl(Hash_function::create(HT_WHIRLPOOL512)));
	default:
		Assert(0, "Hmac_function::create() bad hash type");
		return std::tr1::shared_ptr<Hmac_function>();
	}
}

void
luks::Hmac_impl::init(const uint8_t *key, size_t sz) throw ()
{
	size_t sz_block = block_size();
	if (sz > sz_block) {
		// key too long, so
		// K := H(K)
		_hashfn->init();
		_hashfn->add(key, sz);
		_hashfn->end(_key.get());
		sz = digest_size();
	} else {
		std::copy(key, key + sz, _key.get());
	}

	if (sz < sz_block)
		// (1) fill remainder with zeros
		std::fill(_key.get() + sz, _key.get() + sz_block, 0);

	// (2) XOR result of (1) with ipad
	uint8_t key_ipad[sz_block];
	xor_buf_byte(_key.get(), sz_block, IPAD, key_ipad);

	// done below as well as successive calls to add():
	// (3) append text to result of (2)
	// (4) apply H to result of (3)

	_hashfn->init();
	_hashfn->add(key_ipad, sz_block);
}

void
luks::Hmac_impl::end(uint8_t *out) throw ()
{
	size_t sz_block = block_size();
	uint8_t key_opad[sz_block];
	uint8_t mid_digest[digest_size()];

	// (5) XOR result of (1) with opad
	xor_buf_byte(_key.get(), sz_block, OPAD, key_opad);

	// (6) append result of (4) to result of (5)
	// (7) apply H to result of (6) and output result

	// get H1 = H( K^ipad . data )
	_hashfn->end(mid_digest);
	_hashfn->init();
	_hashfn->add(key_opad, sz_block);
	_hashfn->add(mid_digest, digest_size());
	// get H( K^opad . H1 )
	_hashfn->end(out);
}
