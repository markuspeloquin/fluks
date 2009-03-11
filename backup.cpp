/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <cstring>

#include "backup.hpp"
#include "luks.hpp"
#include "os.hpp"

void
fluks::make_backup(std::sys_fstream &device, const std::string &backup_path)
    throw (boost::system::system_error, Disk_error, No_header,
    Unsupported_version)
{
	struct phdr1 hdr;

	// read the header
	if (!device.seekg(0, std::ios_base::beg))
		throw Disk_error("seek error");
	if (!device.read(reinterpret_cast<char *>(&hdr), sizeof(hdr)))
		throw Disk_error("read error");

	// check the header
	endian_switch(&hdr, false);

	if (!check_magic(&hdr)) throw No_header();
	if (!check_version_1(&hdr)) throw Unsupported_version();
	size_t bytes = sector_size(device) * hdr.off_payload - sizeof(hdr);
	endian_switch(&hdr, false);

	// read the remainder
	boost::scoped_array<char> buf(new char[bytes]);
	device.read(buf.get(), bytes);

	// open dump
	std::ofstream dump(backup_path.c_str(),
	    std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
	if (!dump)
		throw Disk_error("failed to open output file");

	// dump the header
	dump.write(reinterpret_cast<char *>(&hdr), sizeof(hdr));
	dump.write(buf.get(), bytes);
}
