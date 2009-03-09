#ifndef GUTMANN_HPP
#define GUTMANN_HPP

#include <sys/types.h>

#include <fstream>

#include "errors.hpp"

namespace luks {

std::ofstream	&gutmann_erase(std::ofstream &file, off_t pos, size_t bytes)
		    throw (Disk_error);

}

#endif
