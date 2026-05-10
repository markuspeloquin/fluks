#include <linux/fs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>

#include "errors.hpp"
#include "os.hpp"

/** \throw std::system_error */
uint32_t
fluks::num_sectors(int fd) {
	uint64_t sz;
	int sz_sect = sector_size(fd);
	if (ioctl(fd, BLKGETSIZE64, &sz) == -1)
		throw_errno(errno);
	return static_cast<uint32_t>(sz / sz_sect);
}

/** \throw std::system_error */
int
fluks::sector_size(int fd) {
	int sz_sect;
	if (ioctl(fd, BLKSSZGET, &sz_sect) == -1)
		throw_errno(errno);
	return sz_sect;
}

/** \throw std::system_error */
bool
fluks::term_echo() {
	struct termios term;
	if (tcgetattr(STDIN_FILENO, &term) == -1)
		throw_errno(errno);
	return term.c_lflag & ECHO;
}

/** \throw std::system_error */
bool
fluks::term_echo(bool enable) {
	struct termios term;
	bool old;
	if (tcgetattr(STDIN_FILENO, &term) == -1)
		throw_errno(errno);
	old = term.c_lflag & ECHO;
	if (enable)
		term.c_lflag |= ECHO;
	else
		term.c_lflag &= ~ECHO;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == -1)
		throw_errno(errno);
	return old;
}
