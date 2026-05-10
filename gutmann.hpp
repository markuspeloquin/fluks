#ifndef FLUKS_GUTMANN_HPP
#define FLUKS_GUTMANN_HPP

#include <sys/types.h>

namespace fluks {

/** Securely erase data from a location on the hard disk.
 *
 * \param fd	to be erased
 * \param pos	starting position in bytes
 * \param bytes	bytes to be erased
 */
void	gutmann_erase(int fd, off_t pos, size_t bytes);

}

#include "gutmann_private.hpp"

#endif
