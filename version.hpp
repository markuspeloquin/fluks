#ifndef FLUKS_VERSION_HPP
#define FLUKS_VERSION_HPP

#include <sstream>
#include <vector>
#include <boost/foreach.hpp>

namespace fluks {

const unsigned VERSION_BUF[] = { 0, 2 };

class Version {
public:
	/** Construct the current version of fluks. */
	Version() :
		_version(VERSION_BUF,
		    VERSION_BUF + sizeof(VERSION_BUF) / sizeof(*VERSION_BUF))
	{
		init_str();
	}

	/** Create a Version from an iterator. */
	template <typename In>
	Version(In begin, In end) :
		_version(begin, end)
	{
		init_str();
	}

	/** Create a Version from a buffer. */
	Version(const unsigned *version, size_t size) :
		_version(version, version + size)
	{
		init_str();
	}

	/** Get the version as a string. */
	const std::string &str() const
	{	return _str; }

	/** Get the version as a vector. */
	const std::vector<unsigned> &vec() const
	{	return _version; }

	bool operator<(const Version &rhs) const
	{	return cmp(rhs) < 0; }
	bool operator>(const Version &rhs) const
	{	return cmp(rhs) > 0; }
	bool operator<=(const Version &rhs) const
	{	return cmp(rhs) <= 0; }
	bool operator>=(const Version &rhs) const
	{	return cmp(rhs) >= 0; }
	bool operator==(const Version &rhs) const
	{	return cmp(rhs) == 0; }
	bool operator!=(const Version &rhs) const
	{	return cmp(rhs) != 0; }

private:
	int cmp(const Version &rhs) const
	{
		size_t min = _version.size() < rhs._version.size() ?
		    _version.size() : rhs._version.size();
		for (size_t i = 0; i < min; i++) {
			if (_version[i] < rhs._version[i]) return -1;
			if (rhs._version[i] < _version[i]) return 1;
		}
		// if rhs._version is longer, *this < rhs
		if (min != rhs._version.size()) return -1;
		if (min != _version.size()) return 1;
		return 0;
	}

	void init_str()
	{
		std::ostringstream out;
		bool first = true;
		BOOST_FOREACH (unsigned num, _version) {
			if (!first) out << '.';
			first = false;
			out << num;
		}
		_str = out.str();
	}

	std::string		_str;
	std::vector<unsigned>	_version;
};

}

#endif
