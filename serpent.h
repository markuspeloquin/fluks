#ifndef SERPENT_H
#define SERPENT_H

#include <features.h>
#include <stdint.h>

#ifdef __cplusplus
#include <cstddef>
namespace luks {
#else
#include <stddef.h>
#endif

const size_t SERPENT_BLOCK = 16;

/** Key material not of correct length */
const int SERPENT_BAD_KEY_MAT = -1;

struct serpent_key {
      int keyLen;
      uint32_t key[8];
      uint32_t subkeys[33][4];
};

__BEGIN_DECLS

int	serpent_set_key(struct serpent_key *key, const uint8_t *keydata,
	    size_t sz);

void	serpent_encrypt(struct serpent_key *key, const uint8_t *input,
	    uint8_t *out);

void	serpent_decrypt(struct serpent_key *key, const uint8_t *input,
	    uint8_t *out);

__END_DECLS

#ifdef __cplusplus
}
#endif

#endif
