/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

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
