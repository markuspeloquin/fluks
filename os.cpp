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

#include <linux/fs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <boost/system/linux_error.hpp>
#include <boost/system/system_error.hpp>

#include "os.hpp"

uint32_t
fluks::num_sectors(int fd) throw (boost::system::system_error)
{
	uint64_t sz;
	int sz_sect = sector_size(fd);
	if (ioctl(fd, BLKGETSIZE64, &sz) == -1)
		throw_errno(errno);
	return static_cast<uint32_t>(sz / sz_sect);
}

int
fluks::sector_size(int fd) throw (boost::system::system_error)
{
	int sz_sect;
	if (ioctl(fd, BLKSSZGET, &sz_sect) == -1)
		throw_errno(errno);
	return sz_sect;
}

bool
fluks::term_echo() throw (boost::system::system_error)
{
	struct termios term;
	if (tcgetattr(STDIN_FILENO, &term) == -1)
		throw_errno(errno);
	return term.c_lflag & ECHO;
}

bool
fluks::term_echo(bool enable) throw (boost::system::system_error)
{
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
