#ifdef DEBUG

#include <stdio.h>

#include "twofish.h"
#include "twofish_debug.h"
#include "twofish_platform.h"

static inline void
debug_io(const char *s)
{
	printf("%s", s);
}

void
twofish_debug_dump(const void *p, const char *s, int R, uint8_t XOR,
    bool do_rot, bool show_t, bool need_bswap, uint32_t t0, uint32_t t1)
{
	/* build output here */
	const size_t	SZ = 512;
	char		line[SZ];
	uint32_t	q[4];
	size_t		n;

	if (R == IV_ROUND)
		snprintf(line, SZ, "%sIV:    ", s);
	else
		snprintf(line, SZ, "%sR[%2d]: ", s, R);
	for (n = 0; line[n]; n++);

	for (uint8_t i = 0; i < 4; i++) {
		q[i] = ((const uint32_t *)p)[i ^ XOR];
		if (need_bswap) q[i] = Bswap(q[i]);
	}

	snprintf(line + n, SZ - n, "x= %08lX  %08lX  %08lX  %08lX.",
	    (long unsigned)ROR(q[0], do_rot ? R / 2 : 0),
	    (long unsigned)ROL(q[1], do_rot ? R / 2 : 0),
	    (long unsigned)ROR(q[2], do_rot ? (R + 1) / 2 : 0),
	    (long unsigned)ROL(q[3], do_rot ? (R + 1) / 2 : 0));
	while (line[n++]);

	if (show_t) {
		snprintf(line + n, SZ - n,
		    "    t0=%08lX. t1=%08lX.",
		    (long unsigned)t0, (long unsigned)t1);
	}
	while (line[n++]);

	snprintf(line + n, SZ - n, "\n");
	debug_io(line);
}

void
twofish_debug_dump_key(const struct twofish_key *key)
{
	const size_t	SZ = 512;
	char		line[SZ];
	size_t		k64_count = (key->sz_key + 7) / 8;
	unsigned	subkey_count = ROUND_SUBKEYS + 2 * key->numRounds;

	snprintf(line, SZ,
	    ";\n;makeKey:   Input key            -->  S-box key\n");
	debug_io(line);

	/* display in RS format */
	for (size_t i = 0; i < k64_count; i++) {
		snprintf(line, SZ,
		    ";%12s %08lX %08lX  -->  %08lX\n", "",
		    (long unsigned)key->key32[2 * i + 1],
		    (long unsigned)key->key32[2 * i],
		    (long unsigned)key->sboxKeys[k64_count - 1 - i]);
		debug_io(line);
	}
	snprintf(line, SZ, ";%11sSubkeys\n", "");
	debug_io(line);

	for (size_t i = 0; i < subkey_count / 2; i++) {
		snprintf(line, SZ, ";%12s %08lX %08lX%s\n", "",
		    (long unsigned)key->subKeys[2 * i],
		    (long unsigned)key->subKeys[2 * i + 1],
		    2 * i == INPUT_WHITEN ?  "   Input whiten" :
		    2 * i == OUTPUT_WHITEN ? "  Output whiten" :
		    2 * i == ROUND_SUBKEYS ? "  Round subkeys" : "");
		debug_io(line);
	}

	debug_io(";\n");
}

#endif
