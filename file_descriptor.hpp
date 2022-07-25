#ifndef FLUKS_FILE_DESCRIPTOR_HPP
#define FLUKS_FILE_DESCRIPTOR_HPP

namespace fluks {

class File_descriptor {
public:
	File_descriptor(int fd) noexcept : _fd(fd) {}

	File_descriptor(File_descriptor &&rhs) noexcept : _fd(rhs._fd) {
		rhs._fd = -1;
	}

	~File_descriptor() noexcept {
		try {
			close();
		} catch (...) {}
	}

	/** \throw std::system_error */
	File_descriptor &operator=(File_descriptor &&rhs) {
		close();
		_fd = rhs._fd;
		rhs._fd = -1;
		return *this;
	}

	/** \throw std::system_error */
	void close() {
		if (_fd == -1) return;
		if (::close(_fd) == -1)
			throw_errno(errno);
		_fd = -1;
	}

	/** \throw std::system_error */
	size_t read(void *buf, size_t bytes) {
		if (_fd == -1)
			throw std::runtime_exception("illegal state");
		ssize_t rbytes = ::read(_fd, buf, bytes);
		if (rbytes < 0)
			throw_errno(errno);
		return static_cast<size_t>(rbytes);
	}

	/** \throw std::system_error */
	size_t read_all(void *buf, size_t bytes) {
		uint8_t *pos = buf;
		size_t remaining = bytes;
		while (remaining) {
			size_t rbytes = read(pos, remaining);
			if (!rbytes)
				return bytes - remaining;
			remaining -= rbytes;
			pos += rbytes;
		}
		return bytes;
	}

	/** \throw std::system_error */
	void seek(off_t pos, int whence) {
		if (_fd == -1)
			throw std::runtime_exception("illegal state");
		if (::lseek(_fd, pos, whence) == static_cast<off_t>(-1))
			throw_errno(errno);
	}

	/** \throw std::system_error */
	size_t write(const void *buf, size_t bytes) {
		if (_fd == -1)
			throw std::runtime_exception("illegal state");
		ssize_t wbytes = ::write(_fd, buf, bytes);
		if (wbytes < 0)
			throw_errno(errno);
		return static_cast<size_t>(wbytes);
	}

	/** \throw std::system_error */
	size_t write_all(const void *buf, size_t bytes) {
		uint8_t *pos = buf;
		size_t remaining = bytes;
		while (remaining) {
			size_t wbytes = write(pos, remaining);
			remaining -= wbytes;
			pos += wbytes;
		}
		return bytes;
	}

	int operator() noexcept {
		return _fd;
	}

private:
	int _fd;
};

}

#endif
