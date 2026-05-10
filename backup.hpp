#ifndef FLUKS_BACKUP_HPP
#define FLUKS_BACKUP_HPP

#include <string>

namespace fluks {

/** Back up the header and key material.
 * \param device	The hard disk's device
 * \param backup_path	A path to the output file
 * \throws std::system_error
 * \throws Disk_error
 * \throw No_header	LUKS header couldn't be found
 * \throw Unsupported_version	The version in the LUKS header is unrecognized
 */
void	make_backup(int device, const std::string &backup_path);

}

#endif
