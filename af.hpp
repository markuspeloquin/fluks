#ifndef AF_HPP
#define AF_HPP

#include <stdint.h>
#include "luks.hpp"

namespace luks {

// anti-forensic splitting; length of original is (sz), length of
// split version is (sz * stripes); output buffer assumed to be
// the approprate side
void	af_split(const uint8_t *, size_t sz, size_t stripes, enum hash_type,
	    uint8_t *);
void	af_merge(const uint8_t *, size_t sz, size_t stripes, enum hash_type,
	    uint8_t *);

}

#endif
