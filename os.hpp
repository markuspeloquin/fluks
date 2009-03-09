#ifndef FLUKS_OS_HPP
#define FLUKS_OS_HPP

#include <string>

#include "errors.hpp"

namespace fluks {

/** Get the number of sectors in a device
 *
 * \param fildes	The device.
 * \return		The number of sectors.
 * \throw Unix_error	If the ioctl() fails.
 */
uint32_t    num_sectors(int fildes) throw (Unix_error);

/** Get the number of sectors in a device
 *
 * \param fildes	The device.
 * \return		The number of sectors.
 * \throw Unix_error	If the ioctl() fails.
 */
template <class Sys_fstream>
uint32_t    num_sectors(Sys_fstream &device) throw (Unix_error)
{	return num_sectors(device.fd()); }

/** Get the sector size of a device.
 *
 * \param fildes	The device.
 * \return		The sector size.
 * \throw Unix_error	If the ioctl() fails.
 */
int	sector_size(int fildes) throw (Unix_error);

/** Get the sector size of a device.
 *
 * \param device	The device stream.
 * \return		The sector size.
 * \throw Unix_error	If the open() or ioctl() fails (e.g. the device
 *	couldn't be opened).
 */
template <class Sys_fstream>
inline int	sector_size(Sys_fstream &device) throw (Unix_error)
{	return sector_size(device.fd()); }

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
