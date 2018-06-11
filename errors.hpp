/* Copyright (c) 2009-2010, Markus Peloquin <markus@cs.wisc.edu>
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

#ifndef FLUKS_ERRORS_HPP
#define FLUKS_ERRORS_HPP

#include <exception>
#include <string>
#include <boost/system/linux_error.hpp>
#include <boost/system/system_error.hpp>

namespace fluks {


/** Not to be caught.
 *
 * Do not use directly. To conditionally throw an Assertion object, use the
 * Assert() function.
 */
struct Assertion : std::exception {
	Assertion(const std::string &msg) : _msg(msg) {}
	~Assertion() noexcept {}

	const char *what() const noexcept override {
		return _msg.c_str();
	}

	std::string _msg;
};

#ifndef NASSERT
inline void Assert(bool cond, const std::string &msg)
{
	if (!cond) throw Assertion(msg);
}
/* macro version, which short-circuits evaluation of second argument, but
 * it doesn't work well with namespaces */
/*
#	define Assert(cond, msg)				do \
	{							\
		if (!(cond)) throw fluks::Assertion(msg);	\
	}							while(0)
*/
#else
#	define Assert(cond, msg)				do \
	{							\
	}							while(0)
#endif


/** Specified crypto/hash spec was bad */
struct Bad_spec : std::exception {
	Bad_spec(const std::string &msg) : _msg("Bad crypto spec: ") {
		_msg += msg;
	}

	~Bad_spec() noexcept {}

	const char *what() const noexcept override {
		return _msg.c_str();
	}

	std::string _msg;
};

struct Bad_uuid : std::exception {
	Bad_uuid(const std::string &uuid) : _msg("Bad UUID: ") {
		_msg += uuid;
	}

	~Bad_uuid() noexcept {}

	const char *what() const noexcept override {
		return _msg.c_str();
	}

	std::string _msg;
};


struct Crypt_error : virtual std::exception {
	Crypt_error(const std::string &msg) : _msg("Crypto error: ") {
		_msg += msg;
	}

	~Crypt_error() noexcept {}

	const char *what() const noexcept override {
		return _msg.c_str();
	}

	std::string _msg;

protected:
	Crypt_error() {}
};


struct Disk_error : std::exception {
	Disk_error(const std::string &msg) : _msg("Disk error: ") {
		_msg += msg;
	}

	~Disk_error() noexcept {}

	const char *what() const noexcept override {
		return _msg.c_str();
	}

	std::string _msg;
};


/** Device mapper error */
struct Dm_error : std::exception {
	Dm_error(const std::string &msg) : _msg("Device mapper error: ") {
		_msg += msg;
	}

	~Dm_error() noexcept {}

	const char *what() const noexcept override {
		return _msg.c_str();
	}
	std::string _msg;
};


struct Hash_error : virtual std::exception {
};


struct No_header : std::exception {
	~No_header() noexcept {}

	const char *what() const noexcept override {
		return "LUKS header not found";
	}
};


struct No_private_key : std::exception {
	No_private_key() {}
	~No_private_key() noexcept {}

	const char *what() const noexcept override {
		return "The private key hasn't been decrypted yet";
	}
};


/** Thrown if something is probably a bad idea. There is no work-around. */
struct Safety : std::exception {
	Safety(const std::string &msg) : _msg("Safety error: ") {
		_msg += msg;
	}

	~Safety() noexcept {}

	const char *what() const noexcept override {
		return _msg.c_str();
	}

	std::string _msg;
};


struct Slots_full : std::exception {
	~Slots_full() noexcept {}

	const char *what() const noexcept override {
		return "All key slots are used.";
	}
};


/** An SSL error wrapping exception type. */
struct Ssl_error : virtual std::exception {
	Ssl_error();
	~Ssl_error() noexcept {}

	const char *what() const noexcept override {
		return _msg.c_str();
	}

	std::string _msg;
};


/** An SSL crypto error. */
struct Ssl_crypt_error : Crypt_error, Ssl_error {
	Ssl_crypt_error() {}
	~Ssl_crypt_error() noexcept {}

	const char *what() const noexcept override {
		return Ssl_error::what();
	}
};


/** An SSL hashing error. */
struct Ssl_hash_error : Hash_error, Ssl_error {
	Ssl_hash_error() {}
	~Ssl_hash_error() noexcept {}

	const char *what() const noexcept override {
		return Ssl_error::what();
	}
};


struct Unsupported_version : std::exception {
	~Unsupported_version() noexcept {}

	const char *what() const noexcept override {
		return "unsupported LUKS header version";
	}
};

void	throw_errno(int e) throw (boost::system::system_error);

}

#endif
