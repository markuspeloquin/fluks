#include <cstring>

#include "backup.hpp"
#include "luks.hpp"
#include "os.hpp"

void
luks::make_backup(std::sys_fstream &device, const std::string &backup_path)
    throw (Disk_error, No_header, Unix_error, Unsupported_version)
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
