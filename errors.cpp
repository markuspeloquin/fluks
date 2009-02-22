#include <cerrno>
#include <cstring>
#include <sstream>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "errors.hpp"

namespace {

inline void ssl_load_errors()
{
	static bool loaded = false;
	if (!loaded) {
		SSL_load_error_strings();
		loaded = true;
	}
}

}

luks::Ssl_error::Ssl_error()
{
	// '120' comes from ERR_error_string(3); seems like an
	// oversight on their part
	char ssl_err_buf[120];
	ssl_load_errors();
	_msg = "OpenSSL error: ";
	_msg += ERR_error_string(ERR_get_error(), ssl_err_buf);
}

luks::Unix_error::Unix_error(int _errno)
{
	if (!_errno) _errno = errno;
	std::ostringstream out;
	out << "Unix error (" << _errno << "): " << strerror(_errno);
	_msg = out.str();
}
