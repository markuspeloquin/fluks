#ifndef BACKUP_HPP
#define BACKUP_HPP

#include <string>

#include "errors.hpp"
#include "sys_fstream.hpp"

namespace luks {

void	make_backup(std::sys_fstream &device, const std::string &backup_path)
	    throw (Disk_error, No_header, Unix_error, Unsupported_version);

}

#endif
