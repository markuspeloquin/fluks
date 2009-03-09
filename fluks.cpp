#include <ctime>
#include <iostream>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/positional_options.hpp>
#include <boost/program_options/variables_map.hpp>

#include <openssl/rand.h>

#include "backup.hpp"
#include "detect.hpp"
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
	std::cout << "usage: " << prog << " [OPTION ...] DEVICE\n";
	std::cout << desc;
}

} // end unnamed namespace
}

int
main(int argc, char **argv)
{
	using namespace luks;

	namespace po = boost::program_options;

	prog = *argv;

	po::options_description commands_desc("Commands (exactly one)");
	commands_desc.add_options()
	    ("create", "create a LUKS partition header")
	    ("dump", po::value<std::string>(),
		"dump the header and key material to a file")
	    ("help", "show this message")
	    ("list-modes",
		"prints supported ciphers, block modes, hashes, etc.")
	    ("pass", "add a passphrase to a LUKS partition")
	    ;

	po::options_description general_desc("General Options");
	general_desc.add_options()
	    ("info,i", "print the information in the header")
	    ("pretend,p", "do not commit the changes")
	    ;

	po::options_description create_desc("Creation Options");
	create_desc.add_options()
	    ("size,s", po::value<unsigned>(), "master key size (bits)")
	    ("cipher,c", po::value<std::string>(),
		"cipher spec, formatted as "
		"CIPHER[-BLOCK_MODE[-IV_MODE[:IV_HASH]]])\n"
		"  CIPHER: \tencryption cipher\n"
		"  BLOCK_MODE: \tcipher block mode\n"
		"  IV_MODE: \tIV generation mode\n"
		"  IV_HASH: \thash for essiv, and only needed for essiv\n"
		"see --list-modes for possible options")
	    ("hash,h", po::value<std::string>(), "hash spec")
	    ("iter", po::value<unsigned>()->default_value(
		NUM_MK_ITER), "master key iterations")
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

	enum { CREATE, DUMP, LIST_MODES,
	    ADD_PASS, REVOKE_PASS } command;
	uint8_t command_count = 0;

	// get command
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
	if (!var_map["pass"].empty()) {
		command = ADD_PASS;
		command_count++;
	}
	if (!var_map["revoke"].empty()) {
		command = REVOKE_PASS;
		command_count++;
	}

	if (command_count != 1) {
		std::cout << "must specify exactly one command\n";
		return 1;
	}

	if (command == LIST_MODES) {
		list_modes();
		return 0;
	}

	// read device path if needed
	std::string device_path;
	switch (command) {
	case CREATE:
	case DUMP:
	case ADD_PASS:
	case REVOKE_PASS:
		if (var_map["device"].empty()) {
			std::cerr << "must provide a device\n";
			return 1;
		}
		device_path = var_map["device"].as<std::string>();
		break;
	default:;
	}

	bool pretend = !var_map["pretend"].empty();

	if (command == DUMP) {
		if (pretend)
			std::cout << "(--dump command has no pretend mode, "
			    "proceeding...)\n";
		std::string backup_path = var_map["dump"].as<std::string>();
		make_backup(device_path, backup_path);
	}

	// check urandom if needed, seed the random number generator if it
	// doesn't exist
	switch (command) {
	case CREATE:
	case ADD_PASS:
		if (!have_urandom()) {
			std::cerr << "/dev/urandom not found, "
			    "seeding PRNG with clock\n";
			time_t now = time(0);
			RAND_seed(&now, sizeof(now));
		}
		break;
	default:;
	}

	std::tr1::shared_ptr<Luks_header> header;

	if (command == CREATE) {
		// check for mandatory options
		if (var_map["size"].empty()) {
			std::cerr << "--create requires a --size option\n";
			return 1;
		} else if (var_map["cipher"].empty()) {
			std::cerr << "--create requires a --cipher option\n";
			return 1;
		} else if (var_map["hash"].empty()) {
			std::cerr << "--create requires a --hash option\n";
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
		header.reset(new Luks_header(device_path, sz_key,
		    cipher, hash, iter, stripes));

		// get a password
		std::string pass = prompt_passwd("Initial passphrase");
		if (pass.empty())
			return 1;
		header->add_passwd(pass);

		// write to disk
		if (!pretend) header->save();
	} else if (command == ADD_PASS) {
		// read existing header from disk
		header.reset(new Luks_header(device_path));

		// get a password
		std::string pass = prompt_passwd("New passphrase");
		if (pass.empty())
			return 1;

		header->add_passwd(pass);

		// write to disk
		if (!pretend) header->save();
	} else if (command == REVOKE_PASS) {
		header.reset(new Luks_header(device_path));
		std::cout << "First enter a passphrase that will not "
		    "be revoked\n";
		std::string passwd = prompt_passwd("Existing passphrase");
		if (passwd.empty())
			return 1;

		std::string revoke = prompt_passwd("Passphrase to revoke");

		header->revoke_passwd(revoke);
		if (!pretend) header->save();
	}

	if (!var_map["info"].empty())
		header->info();

	return 0;
}
