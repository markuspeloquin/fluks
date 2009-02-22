#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <fcntl.h>

#include <cerrno>
#include <cstring>
#include <sstream>

#include "os.hpp"

luks::Unix_error::Unix_error(int _errno)
{
	if (!_errno) _errno = errno;
	std::ostringstream out;
	out << "Unix error (" << _errno << "): " << strerror(_errno);
	_msg = out.str();
}

int
luks::sector_size(const std::string &device) throw (Unix_error)
{
	int fd;
	int sz_sect;

	if ((fd = open(device.c_str(), O_RDONLY)) == -1) {
		throw Unix_error();
	}
	if (ioctl(fd, BLKSSZGET, &sz_sect) == -1) {
		int e = errno;
		close(fd);
		throw Unix_error(e);
	}

	close(fd);
	return sz_sect;
}
