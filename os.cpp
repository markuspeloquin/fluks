#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>

#include "os.hpp"

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

bool
luks::term_echo() throw (Unix_error)
{
	struct termios term;
	if (tcgetattr(STDIN_FILENO, &term) == -1) throw Unix_error();
	return term.c_lflag & ECHO;
}

bool
luks::term_echo(bool enable) throw (Unix_error)
{
	struct termios term;
	bool old;
	if (tcgetattr(STDIN_FILENO, &term) == -1) throw Unix_error();
	old = term.c_lflag & ECHO;
	if (enable)
		term.c_lflag |= ECHO;
	else
		term.c_lflag &= ~ECHO;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == -1)
		throw Unix_error();
	return old;
}
