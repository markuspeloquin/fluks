#ifndef SUPPORT_HPP
#define SUPPORT_HPP

#include <string>
#include <vector>

#include "luks.hpp"

namespace luks {
namespace cipher_info {

	/** Get the type of a cipher given a name.
	 *
	 * \param name	The name of the cipher algorithm.
	 * \return	The type of the cipher or \link CT_UNDEFINED\endlink.
	 */
	enum cipher_type	type(const std::string &name);

	std::vector<enum cipher_type> types();

	/** Get the name of a cipher in a format the kernel will recognize.
	 *
	 * \param type	The cipher algorithm.
	 * \return	The kernel name of the cipher, or "" if the cipher does
	 *	not exist.
	 */
	const std::string	&name(enum cipher_type type);

	/** Get the kernel name of the given cipher name.
	 *
	 * \param type	The cipher algorithm.
	 * \return	The kernel name of the cipher, or "" if the cipher does
	 *	not exist.
	 */
	inline std::string	canonize(const std::string &n)
	{
		enum cipher_type t = type(n);
		return t == CT_UNDEFINED ? n : name(t);
	}

	/** Get the block size of a cipher.
	 *
	 * \param type	The cipher algorithm.
	 * \return	The block size in bytes, or 0 if the cipher does not
	 *	exist.
	 */
	uint16_t		block_size(enum cipher_type type);

	/** Get the valid %key sizes of a cipher.
	 *
	 * \param type	The cipher algorithm.
	 * \return	The sizes in bytes that are valid, which will be
	 *	empty if the cipher does not exist.
	 */
	std::vector<uint16_t>	key_sizes(enum cipher_type type);

	/** Which version of LUKS is this a part of
	 *
	 * \param typo	The cipher algorithm
	 * \retval 0	The cipher algorithm isn't a part of any standard
	 */
	uint16_t		version(enum cipher_type type);

} namespace hash_info {

	/** Get the type of a hash given a name.
	 *
	 * \param	The name of the hash algorithm.
	 * \return	The type of the hash or \link HT_UNDEFINED\endlink.
	 */
	enum hash_type		type(const std::string &);

	std::vector<enum hash_type> types();

	/** Get the name of a hash in a format the kernel will recognize.
	 *
	 * \param type	The hash algorithm.
	 * \return	The kernel name of the hash, or "" if the hash
	 *	does not exist.
	 */
	const std::string	&name(enum hash_type type);

	/** Get the kernel name of the given hash name.
	 *
	 * \param type	The hash algorithm.
	 * \return	The kernel name of the hash, or "" if the hash
	 *	does not exist.
	 */
	inline std::string	canonize(const std::string &n)
	{
		enum hash_type t = type(n);
		return t == HT_UNDEFINED ? n : name(t);
	}

	/** Get the size of a hash's digest.
	 *
	 * \param type	The hash algorithm.
	 * \return	The size of the hash's digest in bytes, or 0 if
	 *	the hash does not exist.
	 */
	size_t			digest_size(enum hash_type type);

	/** Get the block size of a hash.
	 *
	 * \param type	The hash algorithm.
	 * \return	The block size of the hash in bytes, or 0 if the hash
	 *	does not exist.
	 */
	size_t			block_size(enum hash_type type);

	/** Which version of LUKS is this a part of
	 *
	 * \param typo	The hash algorithm
	 * \retval 0	The hash algorithm isn't a part of any standard
	 */
	uint16_t		version(enum hash_type type);

} namespace block_mode_info {

	enum block_mode		type(const std::string &mode);
	std::vector<enum block_mode> types();
	const std::string	&name(enum block_mode mode);
	uint16_t		version(enum block_mode mode);

} namespace iv_mode_info {

	enum iv_mode		type(const std::string &name);
	std::vector<enum iv_mode> types();
	const std::string	&name(enum iv_mode mode);
	uint16_t		version(enum iv_mode mode);

}
}

#endif
