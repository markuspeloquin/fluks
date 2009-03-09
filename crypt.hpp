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
	/** Create an encryption or decryption object
	 *
	 * \param type	The cipher to use
	 * \return	An object to en/decrypt with.  It's meant to be used
	 *	with the XXX_encrypt() and XXX_decrypt() functions.
	 */
	static std::tr1::shared_ptr<Crypt> create(enum cipher_type type);

	virtual ~Crypt() throw () {}

	/** Set the direction of encryption and the key
	 *
	 * \param dir		One of {<code>DIR_ENCRYPT</code>,
	 *	<code>DIR_DECRYPT</code>}
	 * \param key		The encryption key
	 * \param sz_key	The size of the encryption key in bytes
	 */
	virtual void init(enum crypt_direction dir, const uint8_t *key,
	    size_t sz_key) throw () = 0;

	/** En/Decrypt a block of data
	 *
	 * \param in	The data to be en/decrypted
	 * \param out	The output of the en/decryption
	 * \throw Crypt_error	Typically, this will occur only if the
	 *	init() function was not first called.
	 */
	virtual void crypt(const uint8_t *in, uint8_t *out)
	    throw (Crypt_error) = 0;

	/** Get the block size of the cipher
	 * 
	 * \return	The block size in bytes.
	 */
	virtual size_t block_size() const throw () = 0;
};

/** Encrypt using Cyclic Block Chaining mode
 *
 * The final block is padded as necessary so that the size of the plaintext
 * is a multiple of the cipher's block size.
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization Vector
 * \param[in] in	Plaintext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The ciphertext.  Its size should be at least
 *	<code>ceil(sz_plain/B)</code>, where <code>B</code> is the block
 *	size of the cipher.
 */
void		cbc_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Decrypt using Cyclic Block Chaining mode
 *
 * \param[in] crypter	Block decrypter
 * \param[in] iv	Initialization Vector
 * \param[in] in	Ciphertext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The plaintext.  Its size should be at least
 *	<code>sz_plain</code>.
 */
void		cbc_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Encrypt using Counter mode
 *
 * The plaintext and the ciphertext will have the same length, as counter
 * mode turns the block cipher into a sort of stream cipher.  Encryption
 * and decryption in counter mode are the same.
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization vector
 * \param[in] in	Plaintext
 * \param[in] sz	The size of the plaintext/ciphertext
 * \param[out] out	The ciphertext.  Its size should be at least
 *	<code>sz</code>.
 */
void		ctr_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Decrypt using Counter mode
 *
 * The plaintext and the ciphertext will have the same length, as counter
 * mode turns the block cipher into a sort of stream cipher.  Encryption
 * and decryption in counter mode are the same.
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization vector
 * \param[in] in	Ciphertext
 * \param[in] sz	The size of the plaintext/ciphertext
 * \param[out] out	The plaintext.  Its size should be at least
 *	<code>sz</code>.
 */
inline void	ctr_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz, uint8_t *out);

/** Encrypt using Electronic Code Book mode
 *
 * The most insecure of the encryption modes.  The plaintext is padded so
 * that its size is a multiple of the cipher's block size.
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization vector
 * \param[in] in	Plaintext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The ciphertext.  Its size should be at least
 *	<code>ceil(sz_plain/B)</code>, where <code>B</code> is the block
 *	size of the cipher.
 */
void		ecb_encrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

/** Encrypt using Electronic Code Book mode
 *
 * \param[in] crypter	Block encrypter
 * \param[in] iv	Initialization vector
 * \param[in] in	Ciphertext
 * \param[in] sz_plain	The size of the plaintext
 * \param[out] out	The plaintext.  Its size should be at least
 *	<code>sz_plain</code>.
 */
void		ecb_decrypt(Crypt *crypter, const uint8_t *iv,
		    const uint8_t *in, size_t sz_plain, uint8_t *out);

// the encryption and decryption work the same
inline void
ctr_decrypt(Crypt *crypter, const uint8_t *iv, const uint8_t *in,
    size_t sz, uint8_t *out)
{	ctr_encrypt(crypter, iv, in, sz, out); }

/** AES encryption, using OpenSSL */
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
	AES_KEY			_key;
	enum crypt_direction	_dir;
	bool			_init;
};

}

#endif
