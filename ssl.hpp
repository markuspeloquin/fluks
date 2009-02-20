#ifndef LUKS_SSL_HPP
#define LUKS_SSL_HPP

#include <exception>
#include <string>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace luks {

extern bool ssl_errors_loaded;

inline void ssl_load_errors()
{
	if (!ssl_errors_loaded) {
		SSL_load_error_strings();
		ssl_errors_loaded = true;
	}
}

/** An SSL error wrapping exception type. */
struct Ssl_error : virtual std::exception {
	Ssl_error()
	{
		// for size, see ERR_error_string(3)
		char ssl_err_buf[120];
		ssl_load_errors();
		_msg = "OpenSSL error: ";
		_msg += ERR_error_string(ERR_get_error(), ssl_err_buf);
	}

	~Ssl_error() throw() {}

	const char *what() throw()
	{	return _msg.c_str(); }

	std::string _msg;
};

}

#endif
