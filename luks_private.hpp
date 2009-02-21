#ifndef LUKS_PRIVATE_HPP
#define LUKS_PRIVATE_HPP

#include <arpa/inet.h>

#include <endian.h>

namespace luks {

inline void
endian_switch(uint32_t &x)
{	x = htonl(x); }

inline void
endian_switch(uint16_t &x)
{	x = htons(x); }

}

inline void
luks::endian_switch(struct phdr1 *h, bool process_keys)
{
#if BYTE_ORDER == BIG_ENDIAN
	// don't bother with the rest of the function, though the preprocessor
	// and the inlining compiler would eliminate most of it anyway
	return;
#else
	endian_switch(h->version);
	endian_switch(h->off_payload);
	endian_switch(h->sz_key);
	endian_switch(h->mk_iterations);
	if (!process_keys) return;
	for (size_t i = 0; i < NUM_KEYS; i++)
		endian_switch(h->keys + i);
#endif
}

inline void
luks::endian_switch(struct key *k)
{
#if BYTE_ORDER == BIG_ENDIAN
	return;
#else
	endian_switch(k->active);
	endian_switch(k->iterations);
	endian_switch(k->off_km);
	endian_switch(k->stripes);
#endif
}

#endif
