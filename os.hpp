#ifndef OS_HPP
#define OS_HPP

#include <exception>
#include <string>

namespace luks {

struct Unix_error : std::exception {
	/** Create an error associated with <code>errno</code>.
	 *
	 * \param _errno	The error number, or 0 to use the current
	 *	value.
	 */
	Unix_error(int _errno=0);
	~Unix_error() throw () {}
	const char *what() const throw ()
	{	return _msg.c_str(); }

	std::string _msg;
};

/** Get the sector size of a device.
 *
 * \param device	The device pathname.
 * \return	The sector size.
 * \throw Unix_error	If the open() or ioctl() fails (e.g. the device
 *	couldn't be opened).
 */
int	sector_size(const std::string &device) throw (Unix_error);

}

#endif
