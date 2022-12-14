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
		ERR_load_crypto_strings();
	});
}

}

fluks::Ssl_error::Ssl_error() :
	Ssl_error(ERR_peek_last_error())
{}

fluks::Ssl_error::Ssl_error(unsigned long code) :
        code(code)
{
	ssl_load_errors();
        lib = ERR_lib_error_string(code);
        reason = ERR_reason_error_string(code);

	std::ostringstream out;
	out << "error:" << code << ':' << lib << ':' << reason;
	_msg = out.str();
}

/** \throw std::system_error */
void
fluks::throw_errno(int e) {
	throw std::system_error(e, std::generic_category());
}
