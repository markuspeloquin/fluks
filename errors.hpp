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

#ifndef FLUKS_ERRORS_HPP
#define FLUKS_ERRORS_HPP

#include <exception>
#include <string>

namespace fluks {


/** Not to be caught */
struct Assertion : std::exception {
	Assertion(const std::string &msg) : _msg(msg) {}
	~Assertion() throw () {}
	const char *what() const throw ()
	{	return _msg.c_str(); }
	std::string _msg;
};

#ifndef NASSERT
// use macro to short-circuit the second argument's evaluation
#	define Assert(cond, msg)			do \
	{						\
		if (cond) throw Assertion(msg);		\
	}						while(0)
#else
#	define Assert(cond, msg)			do \
	{						\
	}						while(0)
#endif


/** Specified crypto/hash spec was bad */
struct Bad_spec : std::exception {
	Bad_spec(const std::string &msg) : _msg("Bad crypto spec: ")
	{	_msg += msg; }
	~Bad_spec() throw () {}
	const char *what() const throw ()
	{	return _msg.c_str(); }

	std::string _msg;
};


struct Crypt_error : virtual std::exception {
	Crypt_error(const std::string &msg) : _msg("Crypto error:")
	{	_msg += msg; }
	~Crypt_error() throw () {}
	const char *what() const throw ()
	{	return _msg.c_str(); }
	std::string _msg;
protected:
	Crypt_error() {}
};


struct Disk_error : std::exception {
	Disk_error(const std::string &msg) : _msg("Disk error:")
	{	_msg += msg; }
	~Disk_error() throw () {}
	const char *what() const throw ()
	{	return _msg.c_str(); }
	std::string _msg;
};


/** Device mapper error */
struct Dm_error : std::exception {
	Dm_error(const std::string &msg) : _msg("Device mapper error: ")
	{	_msg += msg; }
	~Dm_error() throw () {}
	const char *what() const throw ()
	{	return _msg.c_str(); }
	std::string _msg;
};


struct Hash_error : virtual std::exception {
};


struct No_header : std::exception {
	~No_header() throw () {}
	const char *what() const throw ()
	{	return "LUKS header not found"; }
};


struct No_private_key : std::exception {
	No_private_key() {}
	~No_private_key() throw () {}
	const char *what() const throw ()
	{	return "The private key hasn't been decrypted yet"; }
};


/** Thrown if something is probably a bad idea.  There is no work-around. */
struct Safety : std::exception {
	Safety(const std::string &msg) : _msg("Safety error: ")
	{	_msg += msg; }
	~Safety() throw () {}
	const char *what() const throw ()
	{	return _msg.c_str(); }
	std::string _msg;
};


struct Slots_full : std::exception {
	~Slots_full() throw() {}
	const char *what() const throw ()
	{	return "All key slots are used."; }
};


/** An SSL error wrapping exception type. */
struct Ssl_error : virtual std::exception {
	Ssl_error();
	~Ssl_error() throw() {}
	const char *what() throw ()
	{	return _msg.c_str(); }

	std::string _msg;
};


/** An SSL crypto error. */
struct Ssl_crypt_error : Crypt_error, Ssl_error {
	Ssl_crypt_error() {}
	~Ssl_crypt_error() throw () {}
	using Ssl_error::what;
};


/** An SSL hashing error. */
struct Ssl_hash_error : Hash_error, Ssl_error {
	Ssl_hash_error() {}
	~Ssl_hash_error() throw () {}
	using Ssl_error::what;
};


struct Unsupported_version : std::exception {
	~Unsupported_version() throw () {}
	const char *what() const throw ()
	{	return "unsupported LUKS header version"; }
};

}

#endif
