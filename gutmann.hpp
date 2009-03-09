#ifndef FLUKS_GUTMANN_HPP
#define FLUKS_GUTMANN_HPP

#include <sys/types.h>

#include <fstream>

#include "errors.hpp"

namespace fluks {

template <class Fstream>
Fstream	&gutmann_erase(Fstream &file, off_t pos, size_t bytes)
	    throw (Disk_error);

}

#include "gutmann_private.hpp"

#endif
