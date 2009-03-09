#include <sys/stat.h>

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

char *prog;

namespace {

void	usage();
bool	have_urandom();

bool
have_urandom()
{
	struct stat st;
	return stat("/dev/urandom", &st) != -1;
}

void
usage(const boost::program_options::options_description &desc)
{
	std::cout << "usage: " << prog << " [OPTION ...] DEVICE\n";
	std::cout << desc;
}

} // end unnamed namespace

int
main(int argc, char **argv)
{
	namespace po = boost::program_options;

	prog = *argv;

	po::options_description general_desc("General Options");
	general_desc.add_options()
	    ("create", "create a LUKS partition header")
	    ("dump", po::value<std::string>(),
		"dump the header and key material to a file")
	    ("help", "show this message")
	    ("info,i", "print the information in the header")
	    ;

	po::options_description create_desc("Creation Options");
	create_desc.add_options()
	    ("size,s", po::value<unsigned>(), "master key size")
	    ("cipher,c", po::value<std::string>(), "cipher spec\n(format is "
		"CIPHER[-BLOCK_MODE[-IV_MODE[:IV_HASH]]])")
	    ("hash,h", po::value<std::string>(), "hash spec")
	    ("iter", po::value<unsigned>()->default_value(
		luks::NUM_MK_ITER), "master key iterations")
	    ("stripes", po::value<unsigned>()->default_value(luks::NUM_STRIPES),
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
	visible_desc.add(general_desc).add(create_desc);

	// combine visible and hidden option groups into 'desc'
	po::options_description desc;
	desc.add(visible_desc).add(hidden_desc);

	po::command_line_parser parser(argc, argv);
	parser.options(desc);
	parser.positional(pos_desc);

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

	if (var_map["device"].empty()) {
		std::cerr << "must provide a device\n";
		return 1;
	}
	std::string device_path = var_map["device"].as<std::string>();

	if (!var_map["dump"].empty()) {
		std::string backup_path = var_map["dump"].as<std::string>();
		luks::make_backup(device_path, backup_path);
	}

	if (!have_urandom()) {
		std::cerr << "/dev/urandom not found, "
		    "seeding PRNG with clock\n";
		time_t now = time(0);
		RAND_seed(&now, sizeof(now));
	}

	std::tr1::shared_ptr<luks::Luks_header> header;

	if (!var_map["create"].empty()) {
		// check for mandatory options
		if (var_map["size"].empty()) {
		} else if (var_map["cipher"].empty()) {
		} else if (var_map["hash"].empty()) {
		}

		unsigned sz_key = var_map["size"].as<unsigned>();
		std::string cipher = var_map["cipher"].as<std::string>();
		std::string hash = var_map["hash"].as<std::string>();
		unsigned iter = var_map["iter"].as<unsigned>();
		unsigned stripes = var_map["stripes"].as<unsigned>();
		header.reset(new luks::Luks_header(device_path, sz_key,
		    cipher, hash, iter, stripes));
	} else {
		header.reset(new luks::Luks_header(device_path));
	}

	if (!var_map["info"].empty())
		header->info();

	return 0;
}
