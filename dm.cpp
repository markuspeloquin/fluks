#include <cstdarg>
#include <cstdio>
#include <iomanip>
#include <sstream>

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

std::string last_error;

extern "C" void dm_logger(int level, const char *file, int line,
    const char *f, ...)
{
	static char *buf = 0;
	static size_t sz = 0;
	va_list ap;

	if (!buf) {
		buf = new char[80];
		sz = 80;
	}

	for (;;) {
		va_start(ap, f);
		int n = vsnprintf(buf, sz, f, ap);
		va_end(ap);

		if (n >= 0) {
			if (static_cast<size_t>(n) < sz) {
				last_error = buf;
				return;
			}

			delete[] buf;
			sz = n + 1;
			buf = new char[sz];
		} else {
			last_error = "vsnprintf() failed; format string: ";
			last_error += f;
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

	if (!(task = dm_task_create(DM_DEVICE_CREATE)))
		throw Dm_error(last_error);

	Dm_task_watch task_watch(task);

	if (!dm_task_set_name(task, name.c_str()))
		throw Dm_error(last_error);

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
		param_out << std::setw(2) << key[i];
	param_out << std::dec << std::setfill(' ');

	// IV_OFFSET = 0
	param_out << " 0 " << device_path << ' ' << start_sector;

	// logical start sector: 0
	if (!dm_task_add_target(task, 0, num_sectors, "crypt",
	    param_out.str().c_str()))
		throw Dm_error(last_error);
}
