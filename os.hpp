#ifndef FLUKS_OS_HPP
#define FLUKS_OS_HPP

#include <cstdint>

namespace fluks {

/** Get the number of sectors in a device
 *
 * \param fildes	The device.
 * \return		The number of sectors.
 * \throw std::system_error	If the ioctl() fails.
 */
uint32_t    num_sectors(int fildes);

/** Get the sector size of a device.
 *
 * \param fildes	The device.
 * \return		The sector size.
 * \throw std::system_error	If the ioctl() fails.
 */
int	sector_size(int fildes);

/** Get terminal echo state
 *
 * \return		The current value
 * \throw std::system_error	The operation failed
 */
bool	term_echo();

/** Set terminal echo
 *
 * \param enable	The state to set the terminal to
 * \return		The old value
 * \throw std::system_error	The operation failed
 */
bool	term_echo(bool enable);

}

#endif
