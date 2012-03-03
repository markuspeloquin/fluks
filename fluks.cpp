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

#include <ctime>
#include <iostream>
#include <boost/filesystem.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/positional_options.hpp>
#include <boost/program_options/variables_map.hpp>

#include <openssl/rand.h>

#include "backup.hpp"
#include "cipher.hpp"
#include "detect.hpp"
#include "dm.hpp"
#include "hash.hpp"
#include "support.hpp"

char *prog;

namespace fluks {
namespace {

const unsigned NUM_TRIES = 3;

void
list_modes()
{
	const std::vector<enum cipher_type> &ciphers = Cipher_traits::types();
	std::vector<enum hash_type> hashes = Hash_traits::types();
	std::vector<enum block_mode> block_modes = block_mode_info::types();
	std::vector<enum iv_mode> iv_modes = iv_mode_info::types();

	std::cout <<
"Entries prefixed with [VERSION] (indicating required version of LUKS) or\n"
"[!] (not in any LUKS spec).\n\n";

	std::cout << "ciphers (with supported key sizes):\n";
	for (std::vector<enum cipher_type>::const_iterator i = ciphers.begin();
	    i != ciphers.end(); ++i) {
		const Cipher_traits *traits = Cipher_traits::traits(*i);

		uint16_t version = traits->luks_version;
		std::cout << "\t[";
		if (!version)	std::cout << '!';
		else		std::cout << version;
		std::cout << "] ";

		std::cout << traits->name << " (";
		for (std::vector<uint16_t>::const_iterator j =
		    traits->key_sizes.begin(); j != traits->key_sizes.end();
		    ++j) {
			if (j != traits->key_sizes.begin())
				std::cout << ' ';
			std::cout << *j * 8;
		}
		std::cout << ")\n";
	}

	std::cout << "\nhashes (with digest size):\n";
	for (std::vector<enum hash_type>::iterator i = hashes.begin();
	    i != hashes.end(); ++i) {

		const Hash_traits *traits = Hash_traits::traits(*i);
		std::cout << "\t[";
		if (!traits->luks_version)
			std::cout << '!';
		else
			std::cout << traits->luks_version;
		std::cout << "] ";

		std::cout << traits->name << " ("
		    << traits->digest_size * 8 << ")\n";
	}

	std::cout << "\nblock modes:\n";
	for (std::vector<enum block_mode>::iterator i = block_modes.begin();
	    i != block_modes.end(); ++i) {

		uint16_t version = block_mode_info::version(*i);
		std::cout << "\t[";
		if (!version)	std::cout << '!';
		else		std::cout << version;
		std::cout << "] ";

		std::cout << block_mode_info::name(*i) << '\n';
	}

	std::cout << "\nIV generation modes:\n";
	for (std::vector<enum iv_mode>::iterator i = iv_modes.begin();
	    i != iv_modes.end(); ++i) {

		uint16_t version = iv_mode_info::version(*i);
		std::cout << "\t[";
		if (!version)	std::cout << '!';
		else		std::cout << version;
		std::cout << "] ";

		std::cout << iv_mode_info::name(*i) << '\n';
	}
}

/** Prompt for a passphrase
 *
 * \param msg		The prompt message.
 * \param repeat	Should the passphrase be repeated for verification?
 * \retval ""		The terminal echo couldn't be reenabled (sorry) or the
 *	passphrases didn't match.
 * \return		The passphrase the user entered
 */
std::string
prompt_passwd(const std::string &msg, bool repeat)
{
	bool echo;

	// disable echo
	try {
		term_echo(false);
		echo = false;
	} catch (const boost::system::system_error &e) {
		std::cerr << "could not disable terminal echo: "
		    << e.what() << '\n';
		echo = true;
	}

	std::cout << msg << (echo ? ": " : " (no echo): ");
	std::string pass;
	std::getline(std::cin, pass);
	std::cout << '\n';

	boost::scoped_ptr<std::string> pass2;
	if (repeat) {
		std::cout << "Repeat" << (echo ? ": " : " (no echo): ");
		pass2.reset(new std::string);
		std::getline(std::cin, *pass2);
		std::cout << '\n';
	}

	// enable echo
	if (!echo) {
		try {
			term_echo(true);
		} catch (const boost::system::system_error &e) {
			std::cerr << "could not reenable terminal echo: "
			    << e.what() << '\n';
			return "";
		}
	}

	if (repeat && pass != *pass2) {
		std::cerr << "Passphrases do not match\n";
		return "";
	}

	return pass;
}

/** Read in a passphrase from a file
 *
 * \param path	The pathname of the file.
 * \retval ""	Error opening/reading file.
 * \return	The passphrase the user entered.
 */
std::string
read_passfile(const std::string &pathname)
{
	std::ifstream file(pathname.c_str());
	if (!file) {
		std::cerr << prog << ": failed to open passphrase file `"
		    << pathname << "'\n";
		return "";
	}

	std::string line;
	if (!std::getline(file, line)) {
		std::cerr << prog << ": failed to read passphrase file `"
		    << pathname << "'\n";
		return "";
	}

	// ideally, there will always be a newline
	if (line[line.size()-1] == '\n')
		line.resize(line.size()-1);
	return line;
}

void
usage(const boost::program_options::options_description &desc)
{
	std::cout
	    << "Usage: " << prog << " COMMAND [OPTION ...] [DEVICE]\n"
	    "DEVICE is usually required, except for the --close and "
	    "--list-modes commands\n\n"
	    "Most common:\n"
	    "    " << prog
	    << " --create [-sSIZE] -cCIPHER_SPEC -hHASH [OPTION ...] DEVICE\n"
	    "    " << prog << " --open NAME [OPTION ...] DEVICE\n"
	    "    " << prog << " --close NAME [OPTION ...]\n"
	    << desc;
}

} // end unnamed namespace
}

int
main(int argc, char **argv)
{
	using namespace fluks;

	namespace fs = boost::filesystem;
	namespace po = boost::program_options;

	prog = *argv;

	po::options_description commands_desc("Commands (at most one)");
	commands_desc.add_options()
	    ("close", po::value<std::string>(),
		"removes the mapping for the named device")
	    ("create", "create a LUKS partition header, writing it to disk")
	    ("dump", po::value<std::string>(),
		"dump the header and key material to a file")
	    ("help", "show this message")
	    ("list-modes", "prints supported ciphers, block modes, "
		"hashes, etc.")
	    ("open", po::value<std::string>(),
		"sets up a LUKS partition with the device mapper with its "
		"name set to the specified argument")
	    ("pass", "add a passphrase to a LUKS partition")
	    ("revoke", "revoke a passphrase of a LUKS partition")
	    ("uuid", "print the UUID of a LUKS partition")
	    ("wipe", "securely erase the LUKS header (will prompt for "
		"confirmation)")
	    ;

	po::options_description general_desc("General Options");
	general_desc.add_options()
	    ("info,i", "print the information in the header (after changes)")
	    ("passfile", po::value <std::string>(),
		"use the first line of this file instead of prompting for "
		"the passphrase")
	    ("newpassfile", po::value <std::string>(),
		"like --passfile but for use with --pass command")
	    ("revokepassfile", po::value <std::string>(),
		"like --passfile but for use with --revoke command")
	    ("pretend,p", "do not commit the changes to disk")
	    ;

	po::options_description create_desc("Creation Options");
	create_desc.add_options()
	    ("size,s", po::value<unsigned>(),
		"master key size in bits (default: maximum possible)")
	    ("cipher,c", po::value<std::string>(),
		"[required] cipher spec, formatted as\n"
		"CIPHER-BLOCK_MODE[-IV_MODE[:IV_HASH]])\n"
		"  CIPHER: \tencryption cipher\n"
		"  BLOCK_MODE: \tcipher block mode\n"
		"  IV_MODE: \tIV generation mode\n"
		"  IV_HASH: \thash for essiv, and only needed for essiv\n"
		"see --list-modes for possible options")
	    ("hash,h", po::value<std::string>(), "[required] hash spec")
	    ("iter", po::value<unsigned>()->default_value(
		NUM_MK_ITER), "master key digest iterations")
	    ("stripes", po::value<unsigned>()->default_value(NUM_STRIPES),
		"number of stripes for key material")
	    ;

	po::options_description hidden_desc;
	hidden_desc.add_options()
	    ("device", po::value<std::string>())
	    ;

	po::positional_options_description pos_desc;
	pos_desc.add("device", 1);

	// combine the visible option groups into 'visible_desc'
	po::options_description visible_desc;
	visible_desc.add(commands_desc).add(general_desc).add(create_desc);

	// combine visible and hidden option groups into 'desc'
	po::options_description desc;
	desc.add(visible_desc).add(hidden_desc);

	// set up the parser
	po::command_line_parser parser(argc, argv);
	parser.options(desc);
	parser.positional(pos_desc);

	// finally parse the arguments, storing into var_map
	po::variables_map var_map;
	try {
		po::store(parser.run(), var_map);
	} catch (const po::unknown_option &e) {
#if BOOST_VERSION >= 104200
		std::cerr << prog << ": unknown option `"
		    << e.get_option_name() << "'\n";
#else
		std::cerr << prog << ": " << e.what() << '\n';
#endif
		return 1;
	}

	if (argc < 2) {
		usage(visible_desc);
		return 1;
	}

	if (!var_map["help"].empty()) {
		usage(visible_desc);
		return 0;
	}

	enum { NO_CMD, CLOSE, CREATE, DUMP, LIST_MODES, OPEN,
	    ADD_PASS, REVOKE_PASS, UUID, WIPE } command = NO_CMD;
	uint8_t command_count = 0;

	// get command
	if (!var_map["close"].empty()) {
		command = CLOSE;
		command_count++;
	}
	if (!var_map["create"].empty()) {
		command = CREATE;
		command_count++;
	}
	if (!var_map["dump"].empty()) {
		command = DUMP;
		command_count++;
	}
	if (!var_map["list-modes"].empty()) {
		command = LIST_MODES;
		command_count++;
	}
	if (!var_map["open"].empty()) {
		command = OPEN;
		command_count++;
	}
	if (!var_map["pass"].empty()) {
		command = ADD_PASS;
		command_count++;
	}
	if (!var_map["revoke"].empty()) {
		command = REVOKE_PASS;
		command_count++;
	}
	if (!var_map["uuid"].empty()) {
		command = UUID;
		command_count++;
	}
	if (!var_map["wipe"].empty()) {
		command = WIPE;
		command_count++;
	}

	if (command_count > 1) {
		std::cout << "must specify at most one command\n";
		return 1;
	}

	bool pretend = !var_map["pretend"].empty();
	bool info = !var_map["info"].empty();
	bool use_passfile = !var_map["passfile"].empty();
	bool use_newpassfile = !var_map["newpassfile"].empty();
	bool use_revokepassfile = !var_map["revokepassfile"].empty();

	// both --info and certain commands require a device
	bool need_device = info;
	switch (command) {
	case CREATE:
	case DUMP:
	case OPEN:
	case ADD_PASS:
	case REVOKE_PASS:
	case UUID:
	case WIPE:
		need_device = true;
	default:;
	}

	// read device path and open device if needed
	std::string device_path;
	std::tr1::shared_ptr<std::sys_fstream> device;
	if (need_device) {
		if (var_map["device"].empty()) {
			std::cout << "must provide a device\n";
			return 1;
		}
		device_path = var_map["device"].as<std::string>();
		std::ios_base::openmode mode =
		    std::ios_base::in | std::ios_base::binary;
		if (!pretend)
			mode |= std::ios_base::out;
		device.reset(
		    new std::sys_fstream(device_path.c_str(), mode));

		if (!*device) {
			std::cerr << prog << ": failed to open device\n";
			return 1;
		}
	}

	// check urandom if needed, seed the random number generator if it
	// doesn't exist
	switch (command) {
	case CREATE:
	case ADD_PASS:
	case WIPE:
		if (!fs::exists(fs::path("/dev/urandom"))) {
			std::cerr << "/dev/urandom not found, "
			    "seeding PRNG with clock\n";
			time_t now = time(0);
			RAND_seed(&now, sizeof(now));
		}
	default:;
	}

	// open the header as needed
	std::tr1::shared_ptr<Luks_header> header;
	bool need_header = false;
	switch (command) {
	case NO_CMD:
		if (info) need_header = true;
		break;
	case OPEN:
	case ADD_PASS:
	case REVOKE_PASS:
	case UUID:
	case WIPE:
		need_header = true;
	default:;
	};
	if (need_header)
		header.reset(new Luks_header(device));

	// execute the command
	switch (command) {
	case NO_CMD:
		break;
	case CLOSE: {
		std::string name = var_map["close"].as<std::string>();
		if (!pretend) {
			dm_close(name);
			std::cout << "Mapping removed\n";
		}
		break;
	}
	case CREATE: {
		// check for mandatory options
		if (var_map["cipher"].empty()) {
			std::cout << "--create requires a --cipher option\n";
			return 1;
		} else if (var_map["hash"].empty()) {
			std::cout << "--create requires a --hash option\n";
			return 1;
		}

		int sz_key;
		std::string cipher = var_map["cipher"].as<std::string>();
		std::string hash = var_map["hash"].as<std::string>();
		unsigned iter = var_map["iter"].as<unsigned>();
		unsigned stripes = var_map["stripes"].as<unsigned>();

		if (var_map["size"].empty())
			sz_key = -1;
		else {
			sz_key = static_cast<int>(
			    var_map["size"].as<unsigned>());
			if (sz_key & 7) {
				std::cerr << "--size argument must be a "
				    "multiple of 8\n";
				return 1;
			}
			sz_key /= 8;
		}

		// create the header
		header.reset(new Luks_header(device, sz_key, cipher, hash,
		    iter, stripes));

		header->check_supported(&std::cerr);

		// get a passphrase
		std::string pass;
		if (use_passfile)
			pass = read_passfile(
			    var_map["passfile"].as<std::string>());
		else
			pass = prompt_passwd("Initial passphrase", true);
		if (pass.empty())
			return 1;
		header->add_passwd(pass);

		// write to disk
		if (!pretend) {
			header->save();
			std::cout << "Header written to disk\n";
		}
		break;
	}
	case DUMP: {
		if (pretend)
			std::cout << "(--dump command has no pretend mode, "
			    "proceeding...)\n";
		std::string backup_path = var_map["dump"].as<std::string>();
		make_backup(*device, backup_path);
		std::cout << "Backup completed\n";
		break;
	}
	case LIST_MODES:
		list_modes();
		break;
	case OPEN: {
		std::string name = var_map["open"].as<std::string>();

		// read passphrase
		std::string pass;
		if (use_passfile) {
			pass = read_passfile(
			    var_map["passfile"].as<std::string>());
			if (pass.empty())
				return 1;
			if (!header->read_key(pass))
				std::cout << "Incorrect passphrase\n";
		} else
			for (unsigned i = 0; i < NUM_TRIES; i++) {
				std::string pass = prompt_passwd("Passphrase",
				    false);
				if (pass.empty())
					return 1;

				if (!header->read_key(pass))
					std::cout << "Incorrect passphrase\n";
				else
					break;
			}

		std::pair<const uint8_t *, size_t> master_key =
		    header->master_key();
		if (!master_key.first)
			// could not be decrypted
			return 1;

		uint32_t num_sect = num_sectors(*device);

		if (!pretend) {
			std::string uuid_str = header->uuid();
			uuid_t uuid;
			if (uuid_parse(uuid_str.c_str(), uuid) != 0)
				throw Bad_uuid(uuid_str);

			dm_open(name,
			    header->sectors(), num_sect - header->sectors(),
			    header->cipher_spec(),
			    master_key.first, master_key.second,
			    uuid,
			    device_path);
			std::cout << "Mapping added\n";
		}

		break;
	}
	case ADD_PASS: {
		std::cout << "First enter a passphrase that has already "
		    "been established with the partition\n";

		// read passphrase
		std::string pass;
		if (use_passfile)
			pass = read_passfile(
			    var_map["passfile"].as<std::string>());
		else
			pass = prompt_passwd("Existing passphrase", false);
		if (pass.empty())
			return 1;

		if (!header->read_key(pass)) {
			std::cerr << "Matching key material not found\n";
			return 1;
		}

		// read NEW passphrase
		std::string newpass;
		if (use_newpassfile)
			newpass = read_passfile(
			    var_map["newpassfile"].as<std::string>());
		else
			newpass = prompt_passwd("New passphrase", true);
		if (newpass.empty())
			return 1;

		header->add_passwd(newpass);

		// write to disk
		if (!pretend) {
			header->save();
			std::cout << "Passphrase added to partition\n";
		}
		break;
	}
	case REVOKE_PASS: {
		std::cout << "First enter a passphrase that will NOT "
		    "be revoked\n";

		// read passphrase
		std::string pass;
		if (use_passfile)
			pass = read_passfile(
			    var_map["passfile"].as<std::string>());
		else
			pass = prompt_passwd("Existing passphrase", false);
		if (pass.empty())
			return 1;

		if (!header->read_key(pass)) {
			std::cerr << "Matching key material not found\n";
			return 1;
		}

		std::cout << "Master key decrypted.\n";

		// read REVOKE passphrase
		std::string revoke;
		if (use_revokepassfile)
			revoke = read_passfile(
			    var_map["revokepassfile"].as<std::string>());
		else
		std::string revoke = prompt_passwd("Passphrase to revoke",
		    false);
		if (revoke.empty())
			return 1;

		if (!header->revoke_passwd(revoke)) {
			std::cerr << "Matching key material not found\n";
			return 1;
		}

		if (!pretend) {
			header->save();
			std::cout << "Key material removed\n";
		}
		break;
	}
	case UUID:
		std::cout << header->uuid() << '\n';
		break;
	case WIPE:
		std::cout << "Are you certain you want to wipe the header, "
		    "making all data inaccessible?\n";

		// read passphrase
		std::string pass;
		if (use_passfile)
			pass = read_passfile(
			    var_map["passfile"].as<std::string>());
		else
			pass = prompt_passwd("Enter passphrase", false);
		if (pass.empty())
			return 1;

		if (!header->read_key(pass)) {
			std::cerr << "Matching key material not found\n";
			return 1;
		}

		if (!pretend) {
			header->wipe();
			std::cout << "LUKS header wiped. I hope you knew "
			    "what you were doing.\n";
		}
		break;
	}

	if (info) {
		if (header)
			std::cout << header->info() << '\n';
		else
			std::cout
			    << "cannot print --info with current command\n";
	}

	return 0;
}
