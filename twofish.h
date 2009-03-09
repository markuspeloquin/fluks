#ifndef TWOFISH_H
#define TWOFISH_H

#include <features.h>
#include <stdint.h>

#ifdef __cplusplus
#include <cstddef>
namespace luks {
#else
#include <stddef.h>
#endif

const size_t TWOFISH_BLOCK = 16;

struct twofish_key {
	uint32_t K[40];
	uint32_t QF[4][256];
};

__BEGIN_DECLS

void	twofish_set_key(struct twofish_key *key, const uint8_t *keydata,
	    size_t sz);

void	twofish_encrypt(struct twofish_key *key, const uint8_t *in,
	    uint8_t *out);

void	twofish_decrypt(struct twofish_key *key, const uint8_t *in,
	    uint8_t *out);

__END_DECLS

#ifdef __cplusplus
}
#endif

#endif
