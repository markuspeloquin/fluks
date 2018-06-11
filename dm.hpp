/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef FLUKS_DM_HPP
#define FLUKS_DM_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#include <boost/uuid/uuid.hpp>

#include "errors.hpp"

namespace fluks {

/** Remove the mapping for a DM device
 *
 * \param name		The name of the mapping
 * \throw Dm_error	An error occurred
 */
void	dm_close(const std::string &name) noexcept(false);

/** Add a mapping for a DM device
 *
 * \param name		The name for the mapping
 * \param start_sector	The start sector of the encrypted data
 * \param num_sectors	The size of the disk minus the start sector
 * \param cipher_spec	A cipher spec to send to dm-crypt (see Linux dm-crypt
 *	documentation)
 * \param key		The master key
 * \param sz_key	The size of the key in bytes
 * \param uuid		The UUID of the device
 * \param device_path	The pathname of the device
 * \throw Dm_error	An error occurred
 */
void	dm_open(const std::string &name,
	    uint64_t start_sector, uint64_t num_sectors,
	    const std::string &cipher_spec,
	    const uint8_t *key, size_t sz_key,
	    const boost::uuids::uuid &uuid,
	    const std::string &device_path)
	    noexcept(false);
}

#endif
