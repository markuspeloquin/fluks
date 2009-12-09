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

#include <cstdarg>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <boost/scoped_array.hpp>

#include "dm.hpp"
#include "libdevmapper.h"

namespace fluks {
namespace {

const size_t UUID_STR_LEN = 36;

std::string log_output;

extern "C" void
dm_logger(int level, const char *file, int line, const char *f, ...)
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
				// the string fit into the buffer
				log_output += buf.get();
				return;
			}

			// buffer not big enough, resize to the proper size
			// (only performed once)
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

class Device_mapper {
public:
	Device_mapper(int type) throw (Dm_error)
	{
		dm_setup_log();

		log_output = "";
		if (!(_task = dm_task_create(type)))
			throw Dm_error(log_output);
	}

	~Device_mapper()
	{
		dm_task_destroy(_task);
	}

	void set_name(const std::string &name) throw (Dm_error)
	{
		log_output = "";
		if (!dm_task_set_name(_task, name.c_str()))
			throw Dm_error(log_output);
	}

	void set_uuid(const uuid_t uuid) throw (Dm_error);

	void run() throw (Dm_error)
	{
		log_output = "";
		if (!dm_task_run(_task))
			throw Dm_error(log_output);
	}

	void add_crypt_target(
	    uint64_t start_sector, uint64_t num_sectors,
	    const std::string &cipher_spec,
	    const uint8_t *key, size_t sz_key,
	    const std::string &device_path) throw (Dm_error);

private:
	struct dm_task *_task;
};

void
Device_mapper::add_crypt_target(
    uint64_t start_sector, uint64_t num_sectors,
    const std::string &cipher_spec,
    const uint8_t *key, size_t sz_key,
    const std::string &device_path) throw (Dm_error)
{
	std::ostringstream param_out;

	// format of param argument:
	//	CIPHER KEY IV_OFFSET DEVICE_PATH OFFSET

	// CIPHER (e.g. serpent-cbc-essiv:tgr192)
	param_out << cipher_spec << ' ';

	// KEY (hex-encoded master key)
	param_out << std::hex << std::setfill('0');
	for (size_t i = 0; i < sz_key; i++)
		param_out << std::setw(2) << (short)key[i];
	param_out << std::dec << std::setfill(' ');

	// IV_OFFSET (number added to sector number for each IV)
	// DEVICE_PATH (e.g. /dev/sda7)
	// OFFSET (start sector number [header is at sector 0])
	param_out << " 0 " << device_path << ' ' << start_sector;

	log_output = "";
	if (!dm_task_add_target(_task,
	    0, // logical start sector
	    num_sectors,
	    "crypt", // DM target
	    param_out.str().c_str()))
		throw Dm_error(log_output);
}

void
Device_mapper::set_uuid(const uuid_t uuid) throw (Dm_error)
{
	char uuid_hex[UUID_STR_LEN + 1];
	uuid_unparse(uuid, uuid_hex);

	log_output = "";
	if (!dm_task_set_uuid(_task, uuid_hex))
		throw Dm_error(log_output);
}

} // end anon namespace
}

void
fluks::dm_close(const std::string &name) throw (Dm_error)
{
	Device_mapper task(DM_DEVICE_REMOVE);
	task.set_name(name);
	task.run();
}

void
fluks::dm_open(const std::string &name,
    uint64_t start_sector, uint64_t num_sectors,
    const std::string &cipher_spec,
    const uint8_t *key, size_t sz_key,
    const uuid_t uuid,
    const std::string &device_path)
    throw (Dm_error)
{
	Device_mapper task(DM_DEVICE_CREATE);
	task.set_name(name);
	task.set_uuid(uuid);
	task.add_crypt_target(start_sector, num_sectors, cipher_spec,
	    key, sz_key, device_path);
	task.run();
}
