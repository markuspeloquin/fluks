#ifndef DM_HPP
#define DM_HPP

#include <stdint.h>

#include <cstddef>
#include <string>

#include "errors.hpp"

namespace luks {

/** Remove the mapping for a DM device
 *
 * \param name		The name of the mapping
 * \throw Dm_error	An error occurred
 */
void	dm_close(const std::string &name) throw (Dm_error);

/** Add a mapping for a DM device
 *
 * \param name		The name for the mapping
 * \param start_sector	The start sector of the encrypted data
 * \param num_sectors	The size of the disk minus the start sector
 * \param cipher_spec	A cipher spec to send to dm-crypt (see Linux dm-crypt
 *	documentation)
 * \param key		The master key
 * \param sz_key	The size of the key in bytes
 * \param device_path	The pathname of the device
 * \throw Dm_error	An error occurred
 */
void	dm_open(const std::string &name, uint64_t start_sector,
	    uint64_t num_sectors, const std::string &cipher_spec,
	    const uint8_t *key, size_t sz_key, const std::string &device_path)
	    throw (Dm_error);
}

#endif
