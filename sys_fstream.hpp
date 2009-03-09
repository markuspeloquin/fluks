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

#ifndef SYS_FSTREAM_HPP
#define SYS_FSTREAM_HPP

#include <fstream>

namespace std {

template<typename _CharT, typename _Traits>
class basic_sys_filebuf : public basic_filebuf<_CharT, _Traits> {
public:
	typedef _CharT					char_type;
	typedef _Traits					traits_type;
	typedef typename traits_type::pos_type		pos_type;
	typedef typename traits_type::off_type		off_type;
	typedef basic_filebuf<_CharT, _Traits>		__filebuf_type;

	// these contrast with basic_filebuf's non-virtual open() function
	__filebuf_type *sys_open(int __fd, ios_base::openmode mode);
	__filebuf_type *sys_open(FILE *__fp, ios_base::openmode mode);

	int fd()
	{ return this->_M_file.fd(); }

	FILE *file()
	{ return this->_M_file.file(); }
};

template <typename _CharT, typename _Traits>
class basic_sys_ifstream : public basic_istream<_CharT, _Traits> {
public:
	typedef _CharT					    char_type;
	typedef _Traits					    traits_type;
	typedef basic_istream<char_type, traits_type>	    __istream_type;
	typedef basic_sys_filebuf<char_type, traits_type>   __filebuf_type;

private:
	__filebuf_type _buf;

public:
	basic_sys_ifstream() :
		__istream_type(),
		_buf()
	{	
		this->init(&_buf);
	}

	explicit basic_sys_ifstream(const char *path,
	    ios_base::openmode mode = ios_base::in) :
		__istream_type(),
		_buf()
	{
		this->init(&_buf);
		this->open(path, mode);
	}

	explicit basic_sys_ifstream(int fd,
	    ios_base::openmode mode = ios_base::in) :
		__istream_type(),
		_buf()
	{
		this->init(&_buf);
		this->open(fd, mode);
	}

	explicit basic_sys_ifstream(FILE *fp,
	    ios_base::openmode mode = ios_base::in) :
		__istream_type(),
		_buf()
	{
		this->init(&_buf);
		this->open(fp, mode);
	}

	~basic_sys_ifstream() {}

	__filebuf_type *rdbuf() const
	{	return const_cast<__filebuf_type *>(&_buf); }

	bool is_open() const
	{	return rdbuf()->is_open(); } 

	void open(const char *path, ios_base::openmode mode = ios_base::in)
	{
		if (!_buf.open(path, mode | ios_base::in))
			this->setstate(ios_base::failbit);
		else
			this->clear();
	}

	void open(int fd, ios_base::openmode mode = ios_base::in)
	{
		if (!_buf.sys_open(fd, mode | ios_base::in))
			this->setstate(ios_base::failbit);
		else
			this->clear();
	}

	void open(FILE *fp, ios_base::openmode mode = ios_base::in)
	{
		if (!_buf.sys_open(fp, mode | ios_base::in))
			this->setstate(ios_base::failbit);
		else
			this->clear();
	}

	void close()
	{	if (!_buf.close()) this->setstate(ios_base::failbit); }

	int fd()
	{	return _buf.fd(); }

	FILE *file()
	{	return _buf.file(); }
};

template <typename _CharT, typename _Traits>
class basic_sys_ofstream : public basic_ostream<_CharT, _Traits> {
public:
	typedef _CharT					    char_type;
	typedef _Traits					    traits_type;
	typedef basic_ostream<char_type, traits_type>	    __ostream_type;
	typedef basic_sys_filebuf<char_type, traits_type>   __filebuf_type;

private:
	__filebuf_type _buf;

public:
	basic_sys_ofstream() :
		__ostream_type(),
		_buf()
	{	
		this->init(&_buf);
	}

	explicit basic_sys_ofstream(const char *path,
	    ios_base::openmode mode = ios_base::out) :
		__ostream_type(),
		_buf()
	{
		this->init(&_buf);
		this->open(path, mode);
	}

	explicit basic_sys_ofstream(int fd,
	    ios_base::openmode mode = ios_base::out) :
		__ostream_type(),
		_buf()
	{
		this->init(&_buf);
		this->open(fd, mode);
	}

	explicit basic_sys_ofstream(FILE *fp,
	    ios_base::openmode mode = ios_base::out) :
		__ostream_type(),
		_buf()
	{
		this->init(&_buf);
		this->open(fp, mode);
	}

	~basic_sys_ofstream() {}

	__filebuf_type *rdbuf() const
	{	return const_cast<__filebuf_type *>(&_buf); }

	bool is_open() const
	{	return rdbuf()->is_open(); }

	void open(const char *path, ios_base::openmode mode = ios_base::out)
	{
		if (!_buf.open(path, mode | ios_base::out))
			this->setstate(ios_base::failbit);
		else
			this->clear();
	}

	void open(int fd, ios_base::openmode mode = ios_base::out)
	{
		if (!_buf.sys_open(fd, mode | ios_base::out))
			this->setstate(ios_base::failbit);
		else
			this->clear();
	}

	void open(FILE *fp, ios_base::openmode mode = ios_base::out)
	{
		if (!_buf.sys_open(fp, mode | ios_base::out))
			this->setstate(ios_base::failbit);
		else
			this->clear();
	}

	void close()
	{	if (!_buf.close()) this->setstate(ios_base::failbit); }

	int fd()
	{	return _buf.fd(); }

	FILE *file()
	{	return _buf.file(); }
};

template <typename _CharT, typename _Traits>
class basic_sys_fstream : public basic_iostream<_CharT, _Traits> {
public:
	typedef _CharT					    char_type;
	typedef _Traits					    traits_type;
	typedef basic_iostream<char_type, traits_type>	    __iostream_type;
	typedef basic_sys_filebuf<char_type, traits_type>   __filebuf_type;

private:
	__filebuf_type _buf;

public:
	basic_sys_fstream() :
		__iostream_type(),
		_buf()
	{	
		this->init(&_buf);
	}

	explicit basic_sys_fstream(const char *path,
	    ios_base::openmode mode = ios_base::out | ios_base::in) :
		__iostream_type(),
		_buf()
	{
		this->init(&_buf);
		this->open(path, mode);
	}

	explicit basic_sys_fstream(int fd,
	    ios_base::openmode mode = ios_base::out | ios_base::in) :
		__iostream_type(),
		_buf()
	{
		this->init(&_buf);
		this->open(fd, mode);
	}

	explicit basic_sys_fstream(FILE *fp,
	    ios_base::openmode mode = ios_base::out | ios_base::in) :
		__iostream_type(),
		_buf()
	{
		this->init(&_buf);
		this->open(fp, mode);
	}

	~basic_sys_fstream() {}

	__filebuf_type *rdbuf() const
	{	return const_cast<__filebuf_type *>(&_buf); }

	bool is_open() const
	{	return rdbuf()->is_open(); }

	void open(const char *path,
	    ios_base::openmode mode = ios_base::out | ios_base::in)
	{
		if (!_buf.open(path,
		    mode | ios_base::out | ios_base::in))
			this->setstate(ios_base::failbit);
		else
			this->clear();
	}

	void open(int fd,
	    ios_base::openmode mode = ios_base::out | ios_base::in)
	{
		if (!_buf.sys_open(fd,
		    mode | ios_base::out | ios_base::in))
			this->setstate(ios_base::failbit);
		else
			this->clear();
	}

	void open(FILE *fp,
	    ios_base::openmode mode = ios_base::out | ios_base::in)
	{
		if (!_buf.sys_open(fp, mode | ios_base::out | ios_base::in))
			this->setstate(ios_base::failbit);
		else
			this->clear();
	}

	void close()
	{	if (!_buf.close()) this->setstate(ios_base::failbit); }

	int fd()
	{	return _buf.fd(); }

	FILE *file()
	{	return _buf.file(); }
};


template<typename _CharT, typename _Traits>
typename basic_sys_filebuf<_CharT, _Traits>::__filebuf_type *
basic_sys_filebuf<_CharT, _Traits>::sys_open(int fd, ios_base::openmode mode)
{
	if (!this->is_open()) {
		this->_M_file.sys_open(fd, mode);
		if (this->is_open()) {
			this->_M_allocate_internal_buffer();
			this->_M_mode = mode;

			// setup initial buffer to 'uncommitted' mode
			this->_M_reading = false;
			this->_M_writing = false;
			this->_M_set_buffer(-1);

			// reset to initial state
			this->_M_state_last = this->_M_state_cur =
			    this->_M_state_beg;

			// 27.8.1.3,4
			if (mode & ios_base::ate &&
			    this->seekoff(0, ios_base::end, mode) ==
			    pos_type(off_type(-1)))
				this->close();
			else
				return this;
		}
	}

	return 0;
}

template<typename _CharT, typename _Traits>
typename basic_sys_filebuf<_CharT, _Traits>::__filebuf_type *
basic_sys_filebuf<_CharT, _Traits>::sys_open(FILE *fp, ios_base::openmode mode)
{
	if (!this->is_open()) {
		this->_M_file.sys_open(fp, mode);
		if (this->is_open()) {
			this->_M_allocate_internal_buffer();
			this->_M_mode = mode;

			// setup initial buffer to 'uncommitted' mode
			this->_M_reading = false;
			this->_M_writing = false;
			this->_M_set_buffer(-1);

			// reset to initial state
			this->_M_state_last = this->_M_state_cur =
			    this->_M_state_beg;

			// 27.8.1.3,4
			if (mode & ios_base::ate &&
			    this->seekoff(0, ios_base::end, mode) ==
			    pos_type(off_type(-1)))
				this->close();
			else
				return this;
		}
	}

	return 0;
}

typedef basic_sys_filebuf <char, char_traits<char> > sys_filebuf;
typedef basic_sys_ifstream<char, char_traits<char> > sys_ifstream;
typedef basic_sys_ofstream<char, char_traits<char> > sys_ofstream;
typedef basic_sys_fstream <char, char_traits<char> > sys_fstream;

}

#endif
