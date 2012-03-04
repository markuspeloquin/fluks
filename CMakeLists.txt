cmake_minimum_required(VERSION 2.4)
set(CMAKE_BUILD_TYPE release)
project(fluks CXX C)

add_definitions(-D_BSD_SOURCE)
set(CMAKE_C_FLAGS         "${CFLAGS} -Wall -std=c99 -pedantic")
set(CMAKE_C_FLAGS_DEBUG   "-O0 -g -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS         "${CXXFLAGS} -Wall -std=c++98")
set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")

add_executable(fluks
	af.cpp
	backup.cpp
	cipher.cpp
	cipher_spec.cpp
	crypt.cpp
	detect.cpp
	dm.cpp
	errors.cpp
	fluks.cpp
	hash.cpp
	hmac.cpp
	luks.cpp
	os.cpp
	pbkdf2.cpp
	support.cpp

	cast6.c
	tiger.c
	twofish.c
	whirlpool.c
	serpent.cpp
)
target_link_libraries(fluks
	boost_filesystem-mt
	boost_program_options-mt
	boost_regex
	boost_system
	devmapper
	ssl
	uuid

	# I seem to need these for static linking
	#crypto
	#dl
	#udev
	#z
)
