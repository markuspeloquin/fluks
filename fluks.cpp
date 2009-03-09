#include <ctime>
#include <iostream>
#include <boost/filesystem.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/positional_options.hpp>
#include <boost/program_options/variables_map.hpp>

#include <openssl/rand.h>

#include "backup.hpp"
#include "detect.hpp"
#include "dm.hpp"
#include "hash.hpp"
#include "support.hpp"

char *prog;

namespace luks {
namespace {

void
list_modes()
{
	std::vector<enum cipher_type> ciphers = cipher_info::types();
	std::vector<enum hash_type> hashes = hash_info::types();
	std::vector<enum block_mode> block_modes = block_mode_info::types();
	std::vector<enum iv_mode> iv_modes = iv_mode_info::types();

	std::cout <<
"Entries prefixed with [VERSION] (indicating required version of LUKS) or\n"
"[!] (not in any LUKS spec).\n\n";

	std::cout << "ciphers (with supported key sizes):\n";
	for (std::vector<enum cipher_type>::iterator i = ciphers.begin();
	    i != ciphers.end(); ++i) {
		std::vector<uint16_t> sizes = cipher_info::key_sizes(*i);

		uint16_t version = cipher_info::version(*i);
		std::cout << "\t[";
		if (!version)	std::cout << '!';
		else		std::cout << version;
		std::cout << "] ";

		std::cout << cipher_info::name(*i) << " (";
		for (std::vector<uint16_t>::iterator j = sizes.begin();
		    j != sizes.end(); ++j) {
			if (j != sizes.begin())
				std::cout << ' ';
			std::cout << *j * 8;
		}
		std::cout << ")\n";
	}

	std::cout << "hashes (with digest size):\n";
	for (std::vector<enum hash_type>::iterator i = hashes.begin();
	    i != hashes.end(); ++i) {

		uint16_t version = hash_info::version(*i);
		std::cout << "\t[";
		if (!version)	std::cout << '!';
		else		std::cout << version;
		std::cout << "] ";

		std::cout << hash_info::name(*i) << " ("
		    << hash_info::digest_size(*i) * 8 << ")\n";
	}

	std::cout << "block modes:\n";
	for (std::vector<enum block_mode>::iterator i = block_modes.begin();
	    i != block_modes.end(); ++i) {

		uint16_t version = block_mode_info::version(*i);
		std::cout << "\t[";
		if (!version)	std::cout << '!';
		else		std::cout << version;
		std::cout << "] ";

		std::cout << block_mode_info::name(*i) << '\n';
	}

	std::cout << "IV generation modes:\n";
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

/** Prompt for a password
 *
 * \param msg	The prompt message.
 * \retval ""	The terminal echo couldn't be reenabled (sorry) or the
 *	passwords didn't match.
 * \return	The password the user entered
 */
std::string
prompt_passwd(const std::string &msg)
{
	bool echo;

	// disable echo
	try {
		term_echo(false);
		echo = false;
	} catch (const Unix_error &e) {
		std::cerr << "could not disable terminal echo: "
		    << e.what() << '\n';
		echo = true;
	}

	std::cout << msg << (echo ? ": " : " (no echo): ");
	std::string pass;
	std::getline(std::cin, pass);

	std::cout << "\nRepeat" << (echo ? ": " : " (no echo): ");
	std::string pass2;
	std::getline(std::cin, pass2);
	std::cout << '\n';

	// enable echo
	if (!echo) {
		try {
			term_echo(true);
		} catch (const Unix_error &e) {
			std::cerr << "could not reenable terminal echo: "
			    << e.what() << '\n';
			return "";
		}
	}

	if (pass != pass2) {
		std::cerr << "Passphrases do not match\n";
		return "";
	}

	return pass;
}

void
usage(const boost::program_options::options_description &desc)
{
	std::cout
	    << "usage: " << prog << " COMMAND [OPTION ...] [DEVICE]\n\n"
	    "DEVICE is usually required, except for the --close and\n"
	    "--list-modes commands\n"
	    << desc;
}

} // end unnamed namespace
}

int
main(int argc, char **argv)
{
	using namespace luks;

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
	    ;

	po::options_description general_desc("General Options");
	general_desc.add_options()
	    ("info,i", "print the information in the header (after changes)")
	    ("pretend,p", "do not commit the changes to disk")
	    ;

	po::options_description create_desc("Creation Options");
	create_desc.add_options()
	    ("size,s", po::value<unsigned>(),
		"[required] master key size in bits")
	    ("cipher,c", po::value<std::string>(),
		"[required] cipher spec, formatted as\n"
		"CIPHER[-BLOCK_MODE[-IV_MODE[:IV_HASH]]])\n"
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
	po::store(parser.run(), var_map);

	if (argc < 2) {
		usage(visible_desc);
		return 1;
	}

	if (!var_map["help"].empty()) {
		usage(visible_desc);
		return 0;
	}

	enum { CLOSE, CREATE, DUMP, LIST_MODES, OPEN,
	    ADD_PASS, REVOKE_PASS, UUID } command;
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

	if (command_count > 1) {
		std::cout << "must specify at most one command\n";
		return 1;
	}

	bool pretend = !var_map["pretend"].empty();

	// read device path and open device if needed
	std::string device_path;
	std::tr1::shared_ptr<std::sys_fstream> device;
	switch (command) {
	case CREATE:
	case DUMP:
	case OPEN:
	case ADD_PASS:
	case REVOKE_PASS:
	case UUID:
		if (var_map["device"].empty()) {
			std::cerr << "must provide a device\n";
			return 1;
		}
		device_path = var_map["device"].as<std::string>();
		{
			std::ios_base::openmode mode =
			    std::ios_base::in | std::ios_base::binary;
			if (!pretend)
				mode |= std::ios_base::out;
			device.reset(
			    new std::sys_fstream(device_path.c_str(), mode));
		}
		break;
	default:;
	}

	// check urandom if needed, seed the random number generator if it
	// doesn't exist
	switch (command) {
	case CREATE:
	case ADD_PASS:
		if (!fs::exists(fs::path("/dev/urandom"))) {
			std::cerr << "/dev/urandom not found, "
			    "seeding PRNG with clock\n";
			time_t now = time(0);
			RAND_seed(&now, sizeof(now));
		}
		break;
	default:;
	}

	// open the header as needed
	std::tr1::shared_ptr<Luks_header> header;
	switch (command) {
	case OPEN:
	case ADD_PASS:
	case REVOKE_PASS:
	case UUID:
		header.reset(new Luks_header(device));
		break;
	default:;
	};

	// execute the command
	switch (command) {
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
		if (var_map["size"].empty()) {
			std::cout << "--create requires a --size option\n";
			return 1;
		} else if (var_map["cipher"].empty()) {
			std::cout << "--create requires a --cipher option\n";
			return 1;
		} else if (var_map["hash"].empty()) {
			std::cout << "--create requires a --hash option\n";
			return 1;
		}

		unsigned sz_key = var_map["size"].as<unsigned>();
		std::string cipher = var_map["cipher"].as<std::string>();
		std::string hash = var_map["hash"].as<std::string>();
		unsigned iter = var_map["iter"].as<unsigned>();
		unsigned stripes = var_map["stripes"].as<unsigned>();

		if (sz_key & 7) {
			std::cerr << "--size argument must be a multiple "
			    "of 8\n";
			return 1;
		}
		sz_key /= 8;

		// create the header
		header.reset(new Luks_header(device, sz_key, cipher, hash,
		    iter, stripes));

		// get a password
		std::string pass = prompt_passwd("Initial passphrase");
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

		// read password
		std::string pass = prompt_passwd("Initial passphrase");
		if (pass.empty())
			return 1;

		if (!header->read_key(pass)) {
			std::cout << "Incorrect password\n";
			return 1;
		}

		std::pair<const uint8_t *, size_t> master_key =
		    header->master_key();
		uint32_t num_sect = num_sectors(*device);

		if (!pretend) {
			dm_open(name, header->sectors(),
			    num_sect - header->sectors(),
			    header->cipher_spec(), master_key.first,
			    master_key.second, device_path);
			std::cout << "Mapping added\n";
		}

		break;
	}
	case ADD_PASS: {
		std::cout << "First enter a passphrase that has already "
		    "been established with the partition\n";
		std::string passwd = prompt_passwd("Existing passphrase");
		if (passwd.empty())
			return 1;

		if (!header->read_key(passwd)) {
			std::cerr << "Matching key material not found\n";
			return 1;
		}

		// get a password
		std::string newpass = prompt_passwd("New passphrase");
		if (newpass.empty())
			return 1;

		header->add_passwd(newpass);

		// write to disk
		if (!pretend) {
			header->save();
			std::cout << "Password added to partition\n";
		}
		break;
	}
	case REVOKE_PASS: {
		std::cout << "First enter a passphrase that will not "
		    "be revoked\n";
		std::string passwd = prompt_passwd("Existing passphrase");
		if (passwd.empty())
			return 1;

		if (!header->read_key(passwd)) {
			std::cerr << "Matching key material not found\n";
			return 1;
		}

		std::cout << "Master key decrypted.\n";

		std::string revoke = prompt_passwd("Passphrase to revoke");
		if (passwd.empty())
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
	}

	if (!var_map["info"].empty()) {
		if (header)
			header->info();
		else
			std::cout
			    << "cannot print --info with current command\n";
	}

	return 0;
}
