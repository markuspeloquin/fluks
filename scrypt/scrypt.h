#ifndef SCRYPT_H
#define SCRYPT_H

#include <features.h>

#ifdef __cplusplus
#	include <cstddef>
#	include <cstdint>
#else
#	include <stddef.h>
#	include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

void
scrypt(const uint8_t *passwd, size_t passwd_len,
    const uint8_t *salt, size_t salt_len,
    unsigned cpu_mem_cost, unsigned r, unsigned parallelization,
    uint8_t *dk, size_t dk_len);

#ifdef __cplusplus
}
#endif

#endif
