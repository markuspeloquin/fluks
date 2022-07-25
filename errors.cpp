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

#include <cerrno>
#include <cstring>
#include <mutex>
#include <sstream>
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

fluks::Ssl_error::Ssl_error(const std::string &msg) {
	ssl_load_errors();

	// '120' used to appear in ERR_error_string(3)
	char ssl_err_buf[120];
	ERR_error_string_n(ERR_get_error(), ssl_err_buf, sizeof ssl_err_buf);

	std::ostringstream out;
	out << msg << ": " << ssl_err_buf;
	_msg = out.str();
}

/** \throw std::system_error */
void
fluks::throw_errno(int e) {
	throw std::system_error(e, std::generic_category());
}
