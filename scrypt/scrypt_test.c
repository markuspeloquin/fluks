#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

struct hmac_sha256_ctx {
	uint8_t outerkey[SHA256_CBLOCK];
	uint8_t innerkey[SHA256_CBLOCK];
};

void	pbkdf2_hmac_sha256(const struct hmac_sha256_ctx *,
	    const uint8_t *, size_t, uint8_t *, uint64_t);

void	hmac_sha256_init(struct hmac_sha256_ctx *, const uint8_t *,
		    size_t);

void
pbkdf2_mine(const uint8_t *passwd, size_t passwd_len,
    const uint8_t *salt, size_t salt_len,
    uint8_t *out, size_t out_len)
{
	struct hmac_sha256_ctx	digest;

	hmac_sha256_init(&digest,
	    passwd, passwd_len);
	pbkdf2_hmac_sha256(&digest,
	    salt, salt_len,
	    out, out_len);
}

void
pbkdf2_openssl(const uint8_t *passwd, size_t passwd_len,
    const uint8_t *salt, size_t salt_len,
    uint8_t *out, size_t out_len)
{
	const EVP_MD	*digest;

	digest = EVP_sha256();
	PKCS5_PBKDF2_HMAC((const char *)passwd, passwd_len,
	    salt, salt_len,
	    1, digest,
	    out_len, out);
}

// 0, 1, 3, 7, 15, 31, 63, 127, 255, 511, ...
#define BITS_TO_SIZE(bits) ((1ULL<<(bits))-1)

uint8_t *
create_random_buffer(size_t size)
{
	uint8_t		*buf;
	uint8_t		*end;

	if (!(buf = malloc(size))) return 0;
	end = buf + size;
	while (end-- != buf)
		*end = rand() & 0xff;
	return buf;
}

int
main(int argc, char **argv)
{
	srand(0);
	int pass_size = 0;
	int salt_size = 0;
	int dk_size = 0;
	while (dk_size < 15) {
		size_t	dk_len;
		size_t	passwd_len;
		size_t	salt_len;
		uint8_t	*dk_mine;
		uint8_t	*dk_ssl;
		uint8_t	*passwd;
		uint8_t	*salt;

		dk_len = BITS_TO_SIZE(dk_size);
		passwd_len = BITS_TO_SIZE(pass_size);
		salt_len = BITS_TO_SIZE(salt_size);

		if (!(passwd = create_random_buffer(passwd_len))) {
			perror(*argv);
			return 1;
		}
		if (!(salt = create_random_buffer(salt_len))) {
			perror(*argv);
			free(passwd);
			return 1;
		}
		if (!(dk_mine = malloc(dk_len))) {
			perror(*argv);
			free(salt);
			free(passwd);
			return 1;
		}
		if (!(dk_ssl = malloc(dk_len))) {
			perror(*argv);
			free(dk_mine);
			free(salt);
			free(passwd);
			return 1;
		}

		pbkdf2_mine(passwd, passwd_len, salt, salt_len,
		    dk_mine, dk_len);
		pbkdf2_openssl(passwd, passwd_len, salt, salt_len,
		    dk_ssl, dk_len);
		free(salt);
		free(passwd);

		int status = 0;
		if (memcmp(dk_mine, dk_ssl, dk_len))
			status = 1;
		free(dk_ssl);
		free(dk_mine);

		printf("pass_size=%2d salt_size=%2d dk_size=%2d: %s\n",
		    pass_size, salt_size, dk_size,
		    status ? "failed" : "passed");
		if (status)
			return status;

		if (++dk_size != 15)
			; // good
		else if (++salt_size != 15)
			dk_size = 0;
		else if (++pass_size != 15)
			dk_size = salt_size = 0;
	}
	return 0;
}
