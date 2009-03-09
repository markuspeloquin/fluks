#include <cstdarg>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <boost/scoped_array.hpp>

#include "dm.hpp"
#include "libdevmapper.h"

namespace {

struct Dm_task_watch {
	Dm_task_watch(struct dm_task *task) : _task(task) {}
	~Dm_task_watch()
	{
		dm_task_destroy(_task);
	}

	struct dm_task *_task;
};

std::string log_output;

extern "C" void dm_logger(int level, const char *file, int line,
    const char *f, ...)
{
	if (level > 3) return;

	const int SZ = 100;
	boost::scoped_array<char> buf(new char[SZ]);
	int sz = SZ;
	va_list ap;

	log_output += "\n\t";

	for (;;) {
		va_start(ap, f);
		int n = vsnprintf(buf.get(), sz, f, ap);
		va_end(ap);

		if (n >= 0) {
			if (n < sz) {
				log_output += buf.get();
				return;
			}

			sz = n + 1;
			buf.reset(new char[sz]);
		} else {
			log_output += "vsnprintf() failed; ";
			log_output += file;
			log_output += ": ";
			log_output += f;
			return;
		}
	}
}

void dm_setup_log()
{
	static bool needed = true;
	if (!needed) return;

	dm_log_init(dm_logger);
	needed = false;
}

} // end anon namespace

void
luks::dm_create(const std::string &name, uint64_t start_sector,
    uint64_t num_sectors, const std::string &cipher_spec,
    const uint8_t *key, size_t sz_key, const std::string &device_path)
    throw (Dm_error)
{
	std::ostringstream param_out;
	struct dm_task *task;

	dm_setup_log();

	log_output = "";
	if (!(task = dm_task_create(DM_DEVICE_CREATE)))
		throw Dm_error(log_output);

	Dm_task_watch task_watch(task);

	log_output = "";
	if (!dm_task_set_name(task, name.c_str()))
		throw Dm_error(log_output);

	// format of param argument:
	//	CIPHER KEY IV_OFFSET DEVICE_PATH OFFSET
	// CIPHER: (e.g. serpent-cbc-essiv:tgr192)
	// KEY: hexadecimal-encoded master key
	// IV_OFFSET: number added to sector number for each IV calculation
	// DEVICE_PATH: (e.g. /dev/sda7)
	// OFFSET: start sector number (header is at sector 0)

	param_out << cipher_spec << ' ';

	param_out << std::hex << std::setfill('0');
	for (size_t i = 0; i < sz_key; i++)
		param_out << std::setw(2) << (short)key[i];
	param_out << std::dec << std::setfill(' ');

	// IV_OFFSET = 0
	param_out << " 0 " << device_path << ' ' << start_sector;

	std::cerr << "dm_task_add_target(task, 0, " << num_sectors
	    << ", \"crypt\", " << param_out.str() << ");\n";

	// logical start sector: 0
	log_output = "";
	if (!dm_task_add_target(task, 0, num_sectors, "crypt",
	    param_out.str().c_str()))
		throw Dm_error(log_output);

	log_output = "";
	if (!dm_task_run(task))
		throw Dm_error(log_output);
}
