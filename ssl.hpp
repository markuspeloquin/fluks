#ifndef LUKS_SSL_HPP
#define LUKS_SSL_HPP

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

}

#endif
