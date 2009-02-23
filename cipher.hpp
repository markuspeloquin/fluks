#ifndef LUKS_CIPHER_HPP
#define LUKS_CIPHER_HPP

#include <string>
#include <vector>

#include "luks.hpp"

namespace luks {

/** Get the type of a cipher given a name.
 *
 * \param name	The name of the cipher algorithm.
 * \return	The type of the cipher or \link CT_UNDEFINED\endlink.
 */
enum cipher_type	get_cipher_type(const std::string &name);

/** Get the name of a cipher in a format the kernel will recognize.
 *
 * \param type	The cipher algorithm.
 * \return	The kernel name of the cipher, or "" if the cipher does
 *	not exist.
 */
std::string		cipher_name(enum cipher_type type);

/** Get the kernel name of the given cipher name.
 *
 * \param type	The cipher algorithm.
 * \return	The kernel name of the cipher, or "" if the cipher does
 *	not exist.
 */
inline std::string	cipher_canonize(const std::string &name)
{
	enum cipher_type t = get_cipher_type(name);
	return t == CT_UNDEFINED ? name : cipher_name(t);
}

/** Get the block size of a cipher.
 *
 * \param type	The cipher algorithm.
 * \return	The block size in bytes, or 0 if the cipher does not exist.
 */
uint16_t		cipher_block_size(enum cipher_type type);

/** Get the valid %key sizes of a cipher.
 *
 * \param type	The cipher algorithm.
 * \return	The sizes in bytes that are valid, which will be empty if the
 *	cipher does not exist.
 */
std::vector<uint16_t>	cipher_key_sizes(enum cipher_type type);

}

#endif
