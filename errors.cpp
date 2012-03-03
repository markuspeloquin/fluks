/* Copyright (c) 2009, Markus Peloquin <markus@cs.wisc.edu>
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

fluks::Ssl_error::Ssl_error()
{
	// '120' comes from ERR_error_string(3); seems like an
	// oversight on their part
	char ssl_err_buf[120];
	ssl_load_errors();
	_msg = "OpenSSL error: ";
	_msg += ERR_error_string(ERR_get_error(), ssl_err_buf);
}

void
fluks::throw_errno(int e) throw (boost::system::system_error)
{
	// wow
	throw boost::system::system_error(
	    boost::system::linux_error::make_error_code(
	    static_cast<boost::system::linux_error::linux_errno>(e)));
}
