#ifndef CRYPT_HPP
#define CRYPT_HPP

#include <tr1/memory>

#include <openssl/aes.h>

#include "luks.hpp"

namespace luks {

enum crypt_direction { DIR_ENCRYPT, DIR_DECRYPT };

/** En/Decrypt a block of data */
class Crypt {
	// CRYPTER! CRYPTER! CRYPTER!
public:
	static std::tr1::shared_ptr<Crypt> create(enum cipher_type type);

	virtual ~Crypt() throw () {}
	virtual void init(enum crypt_direction dir, const uint8_t *key,
	    size_t sz_key) throw () = 0;

	virtual void crypt(const uint8_t *in, uint8_t *out)
	    throw (Crypt_error) = 0;

	virtual size_t block_size() const throw () = 0;
};

void		cbc_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_in, uint8_t *out);

void		cbc_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_in, uint8_t *out);

void		ctr_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_in, uint8_t *out);

inline void	ctr_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_in, uint8_t *out);

void		cts_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_in, uint8_t *out);

void		cts_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_in, uint8_t *out);

void		ecb_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_in, uint8_t *out);

void		ecb_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_in, uint8_t *out);

// the encryption and decryption work the same
inline void
ctr_decrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz_in, uint8_t *out)
{	ctr_encrypt(crypter, iv, in, sz_in, out); }

class Crypt_aes : public Crypt {
public:
	Crypt_aes() : _init(false) {}
	~Crypt_aes() throw () {}

	void init(enum crypt_direction dir, const uint8_t *key, size_t sz_key)
	    throw ()
	{
		_dir = dir;
		if (_dir == DIR_ENCRYPT)
			AES_set_encrypt_key(key, sz_key * 8, &_key);
		else
			AES_set_decrypt_key(key, sz_key * 8, &_key);
		_init = true;
	}
	void crypt(const uint8_t *in, uint8_t *out) throw (Crypt_error)
	{
		if (!_init)
			throw Crypt_error(_dir == DIR_ENCRYPT ?
			    "no encryption key set" :
			    "no decryption key set");
		if (_dir == DIR_ENCRYPT)
			AES_encrypt(in, out, &_key);
		else
			AES_decrypt(in, out, &_key);
	}
	size_t block_size() const throw ()
	{	return AES_BLOCK_SIZE; }

private:
	AES_KEY _key;
	enum crypt_direction _dir;
	bool _init;
};

}

#endif
