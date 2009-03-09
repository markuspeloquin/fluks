#ifndef GUTMANN_HPP
#define GUTMANN_HPP

#include <sys/types.h>

#include <fstream>

#include "errors.hpp"

namespace luks {

template <class Fstream>
Fstream	&gutmann_erase(Fstream &file, off_t pos, size_t bytes)
	    throw (Disk_error);

}

#include "gutmann_private.hpp"

#endif
