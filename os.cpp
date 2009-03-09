#include <linux/fs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>

#include "os.hpp"

uint32_t
luks::num_sectors(int fd) throw (Unix_error)
{
	uint64_t sz;
	int sz_sect = sector_size(fd);
	if (ioctl(fd, BLKGETSIZE64, &sz) == -1) {
		int e = errno;
		close(fd);
		throw Unix_error(e);
	}
	return static_cast<uint32_t>(sz / sz_sect);
}

int
luks::sector_size(int fd) throw (Unix_error)
{
	int sz_sect;
	if (ioctl(fd, BLKSSZGET, &sz_sect) == -1) {
		int e = errno;
		close(fd);
		throw Unix_error(e);
	}
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
