#include <format>
#include <mutex>
#include <system_error>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "errors.hpp"

namespace {

inline void
ssl_load_errors() {
	static std::once_flag flag;
	std::call_once(flag, []() {
		SSL_load_error_strings();
	});
}

}

fluks::Ssl_error::Ssl_error(std::string_view msg) {
	ssl_load_errors();

	// '120' used to appear in ERR_error_string(3)
	char ssl_err_buf[120];
	ERR_error_string_n(ERR_get_error(), ssl_err_buf, sizeof ssl_err_buf);

	_msg = std::format("{}: {}", msg, ssl_err_buf);
}

/** \throw std::system_error */
void
fluks::throw_errno(int e) {
	throw std::system_error(e, std::generic_category());
}
