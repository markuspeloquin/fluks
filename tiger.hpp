#ifndef TIGER_HPP
#define TIGER_HPP

#include <stdint.h>

#include <cstddef>

namespace luks {

struct tiger_ctx {
	uint8_t		buf[64];
	uint64_t	res[3];
	uint64_t	length;
	size_t		sz;
	int		passes;
};

void	tiger_init(struct tiger_ctx *ctx, int passes);
void	tiger_update(struct tiger_ctx *ctx, const uint8_t *buf, size_t sz);
void	tiger_end(struct tiger_ctx *ctx, uint8_t *res);

void	tiger_impl(const uint8_t *str, uint64_t length, int passes,
	    uint64_t res[3]);

}

#endif
