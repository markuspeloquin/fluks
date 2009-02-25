#ifndef ERRORS_HPP
#define ERRORS_HPP

#include <exception>
#include <string>

namespace luks {


struct Bad_spec : std::exception {
	Bad_spec(const std::string &msg) : _msg("Bad crypto spec: ")
	{	_msg += msg; }
	~Bad_spec() throw () {}
	const char *what() const throw ()
	{	return _msg.c_str(); }

	std::string _msg;
};


struct Crypt_error : std::exception {
	Crypt_error(const std::string &msg) : _msg("Crypto error:")
	{	_msg += msg; }
	~Crypt_error() throw () {}
	const char *what() const throw ()
	{	return _msg.c_str(); }
	std::string _msg;
};


struct Hash_error : virtual std::exception {
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
	const char *what() throw()
	{	return _msg.c_str(); }

	std::string _msg;
};


/** An SSL hashing error. */
struct Ssl_hash_error : Hash_error, Ssl_error {
	Ssl_hash_error() {}
	~Ssl_hash_error() throw() {}
};


struct Unix_error : std::exception {
	/** Create an error associated with <code>errno</code>.
	 *
	 * \param _errno	The error number, or 0 to use the current
	 *	value.
	 */
	Unix_error(int _errno=0);
	~Unix_error() throw () {}
	const char *what() const throw ()
	{	return _msg.c_str(); }

	std::string _msg;
};

}

#endif
