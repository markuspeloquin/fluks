#include <cstring>
#include <fstream>

#include "backup.hpp"
#include "luks.hpp"
#include "os.hpp"

void
luks::make_backup(const std::string &device_path,
    const std::string &backup_path)
    throw (Disk_error, Unix_error, Unsupported_version)
{
	struct phdr1 hdr;

	// open device
	std::ifstream dev(device_path.c_str(),
	    std::ios_base::binary | std::ios_base::in);
	if (!dev)
		throw Disk_error("failed to open device");

	// read the header
	dev.read(reinterpret_cast<char *>(&hdr), sizeof(hdr));
	if (!dev)
		throw Disk_error("read error");

	// check the header
	endian_switch(&hdr, false);
	if (!header_version_1(&hdr))
		throw Unsupported_version();
	size_t bytes = sector_size(device_path) * hdr.off_payload -
	    sizeof(hdr);
	endian_switch(&hdr, false);

	// read the remainder
	boost::scoped_array<char> buf(new char[bytes]);
	dev.read(buf.get(), bytes);
	dev.close();

	// open dump
	std::ofstream dump(backup_path.c_str(),
	    std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
	if (!dump)
		throw Disk_error("failed to open output file");

	// dump the header
	dump.write(reinterpret_cast<char *>(&hdr), sizeof(hdr));
	dump.write(buf.get(), bytes);
}
