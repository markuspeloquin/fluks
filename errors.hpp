#ifndef ERRORS_HPP
#define ERRORS_HPP

#include <exception>
#include <string>

namespace luks {


/** Not to be caught */
struct Assertion : std::exception {
	Assertion(const std::string &msg) : _msg(msg) {}
	~Assertion() throw () {}
	const char *what() const throw ()
	{	return _msg.c_str(); }
	std::string _msg;
};

inline void	Assert(bool cond, const std::string &msg)
{
#ifndef NDEBUG
	if (!cond) throw Assertion(msg);
#endif
}

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


struct Disk_error : std::exception {
	Disk_error(const std::string &msg) : _msg("Disk error:")
	{	_msg += msg; }
	~Disk_error() throw () {}
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


struct Safety : std::exception {
	Safety(const std::string &msg) : _msg("Safety error: ")
	{
		_msg += msg;
	}
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


/** An SSL hashing error. */
struct Ssl_hash_error : Hash_error, Ssl_error {
	Ssl_hash_error() {}
	~Ssl_hash_error() throw () {}
	using Ssl_error::what;
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


struct Unsupported_version : std::exception {
	~Unsupported_version() throw () {}
	const char *what() const throw ()
	{	return "unsupported LUKS header version"; }
};

}

#endif
