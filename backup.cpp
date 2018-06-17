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

#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>

#include "backup.hpp"
#include "errors.hpp"
#include "luks.hpp"
#include "os.hpp"

namespace fluks {
namespace {

void
read_all(int fd, void *buf, size_t count) {
	uint8_t *pos = static_cast<uint8_t *>(buf);
	while (count) {
		ssize_t by = read(fd, pos, count);
		if (by < 0)
			throw_errno(errno);
		if (!by)
			throw Disk_error("premature EOF");
		count -= by;
		pos += by;
	}
}

}
}

/**
 * \throws boost::system::system_error
 * \throws Disk_error
 * \throws No_header
 * \throws Unsupported_version
 */
void
fluks::make_backup(int device, const std::string &backup_path) {
	struct phdr1 hdr;

	// read the header
	if (lseek(device, 0, SEEK_SET) == static_cast<off_t>(-1))
		throw_errno(errno);
	read_all(device, &hdr, sizeof hdr);

	// check the header
	endian_switch(&hdr, false);

	if (!check_magic(&hdr)) throw No_header();
	if (!check_version_1(&hdr)) throw Unsupported_version();
	size_t bytes = sector_size(device) * hdr.off_payload - sizeof hdr;
	endian_switch(&hdr, false);

	// read the remainder
	std::unique_ptr<char[]> buf{new char[bytes]};
	read_all(device, buf.get(), bytes);

	// open dump
	std::ofstream dump(backup_path.c_str(),
	    std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
	if (!dump)
		throw Disk_error("failed to open output file");

	// dump the header
	dump.write(reinterpret_cast<char *>(&hdr), sizeof hdr);
	dump.write(buf.get(), bytes);
}
