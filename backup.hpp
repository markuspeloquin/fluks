#ifndef BACKUP_HPP
#define BACKUP_HPP

#include <string>

#include "errors.hpp"

namespace luks {

void	make_backup(const std::string &device_path,
	    const std::string &backup_path)
	    throw (Disk_error, Unix_error, Unsupported_version);

}

#endif
