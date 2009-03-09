#include <sys/stat.h>

#include <ctime>
#include <iostream>

#include <openssl/rand.h>

#include "hash.hpp"
#include "detect.hpp"

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
usage()
{
	std::cout << "usage: " << prog << " ARGS...\n";
}

} // end unnamed namespace

int
main(int argc, char **argv)
{
	prog = *argv;
	if (argc < 2) {
		usage();
		return 1;
	}

	if (!have_urandom()) {
		time_t now = time(0);
		std::cerr << "/dev/urandom not found, "
		    "seeding PRNG with clock\n";
		RAND_seed(&now, sizeof(now));
	}

	luks::Luks_header header(argv[1]);

	return 0;
}
