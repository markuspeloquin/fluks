#ifndef OS_HPP
#define OS_HPP

#include <string>

#include "errors.hpp"

namespace luks {

/** Get the sector size of a device.
 *
 * \param device	The device pathname.
 * \return	The sector size.
 * \throw Unix_error	If the open() or ioctl() fails (e.g. the device
 *	couldn't be opened).
 */
int	sector_size(const std::string &device) throw (Unix_error);

/** Get terminal echo state
 *
 * \return		The current value
 * \throw Unix_error	The operation failed
 */
bool	term_echo() throw (Unix_error);

/** Set terminal echo
 *
 * \param enable	The state to set the terminal to
 * \return		The old value
 * \throw Unix_error	The operation failed
 */
bool	term_echo(bool enable) throw (Unix_error);

}

#endif
