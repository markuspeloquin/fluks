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
		assert(0);
		return std::tr1::shared_ptr<Hmac_function>();
	}
}

void
luks::Hmac_impl::init(const uint8_t *key, size_t sz) throw (std::length_error)
{
	size_t sz_block = blocksize();
	if (sz > sz_block)
		throw std::length_error(
		    "HMAC key length cannot exceed the block size "
		    "of the hash");

	std::copy(key, key + sz, _key.get());
	if (sz < sz_block)
		std::fill(_key.get() + sz, _key.get() + sz_block, 0);

	uint8_t key_ipad[sz_block];
	xor_bufs(_key.get(), _ipad.get(), sz_block, key_ipad);

	_hashfn->init();
	_hashfn->add(key_ipad, sz_block);
}

void
luks::Hmac_impl::end(uint8_t *out) throw()
{
	size_t sz_block = blocksize();

	uint8_t key_opad[sz_block];
	uint8_t mid_digest[length()];
	xor_bufs(_key.get(), _opad.get(), sz_block, key_opad);
	// get H1 = H( K^ipad . data )
	_hashfn->end(mid_digest);
	_hashfn->init();
	_hashfn->add(key_opad, sz_block);
	_hashfn->add(mid_digest, length());
	// get H( K^opad . H1 )
	_hashfn->end(out);
}
