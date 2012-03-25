cmake_minimum_required(VERSION 2.8)

enable_testing()


# START OF USER CONFIG

# remember to do a `make clean` and `rm CMakeCache.txt` after changing this
set(static_linking true)

set(CMAKE_BUILD_TYPE release)

# END OF USER CONFIG (glad that's over)


project(fluks CXX C)

set(Boost_USE_STATIC_LIBS ${static_linking})
set(Boost_USE_MULTITHREADED true)
#set(Boost_USE_STATIC_RUNTIME true)

find_package(Boost 1.35 COMPONENTS filesystem program_options regex system)

set(ORIG_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
if(static_linking)
	set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
endif()

find_library(OPENSSL_libssl ssl DOC "OpenSSL libssl")
find_library(OPENSSL_libcrypto crypto DOC "OpenSSL libcrypto")
find_path(OPENSSL_INCLUDE_DIR openssl/ssl.h DOC "OpenSSL headers")
if(${OPENSSL_libssl} STREQUAL "OPENSSL_libssl-NOTFOUND" OR
    ${OPENSSL_libcrypto} STREQUAL "OPENSSL_libcrypto-NOTFOUND" OR
    ${OPENSSL_INCLUDE_DIR} STREQUAL "OPENSSL_INCLUDE_DIR-NOTFOUND")
	message(FATAL_ERROR "OpenSSL not found")
endif()
message(STATUS "OpenSSL found")

find_library(DEVICE_MAPPER_libdevmapper devmapper
    DOC "Device Mapper (libdevmapper)")
if(${DEVICE_MAPPER_libdevmapper} STREQUAL
    "DEVICE_MAPPER_libdevmapper-NOTFOUND")
	message(FATAL_ERROR "Device Mapper libdevmapper not found")
endif()
message(STATUS "Device Mapper libdevmapper found")

# Ubuntu needs these I think?
find_library(SE_libselinux selinux DOC "SE libselinux")
find_library(SE_libsepol sepol DOC "SE libsepol")
if (${SE_libselinux} STREQUAL "SE_libselinux-NOTFOUND")
	message(STATUS "libselinux not found")
	set(SE_libselinux "")
else()
	message(STATUS "libselinux found")
endif()
if (${SE_libsepol} STREQUAL "SE_libsepol-NOTFOUND")
	message(STATUS "libsepol not found")
	set(SE_libsepol "")
else()
	message(STATUS "libsepol found")
endif()

if(static_linking)
	# required by libdevmapper.a
	find_library(UDEV_libudev udev DOC "libudev")
	if(${UDEV_libudev} STREQUAL "UDEV_libudev-NOTFOUND")
		message(FATAL_ERROR "libudev not found")
	endif()
	message(STATUS "libudev found")

	# required by libcrypto.a
	find_library(ZLIB_libz z DOC "zlib")
	if(${ZLIB_libz} STREQUAL "ZLIB_libz-NOTFOUND")
		message(FATAL_ERROR "zlib not found")
	endif()
	message(STATUS "zlib found")

	# required by libudev.a
	set(LIBC_librt librt.a)

	# required by librt.a, libcrypto.a
	set(LIBC_libdl libdl.a)

	# i forget why
	set(LIBC_libpthread libpthread.a)

	# add a '-Wl,-Bstatic' to the end so all the gcc libraries will be
	# static
	set(static_link_header "-static")
	set(static_link_footer "-Wl,-Bstatic")
endif()

# revert to old setting
set(CMAKE_FIND_LIBRARY_SUFFIXES ${ORIG_CMAKE_FIND_LIBRARY_SUFFIXES})

include_directories(${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
add_definitions(-D_BSD_SOURCE)
set(CMAKE_C_FLAGS         "${CFLAGS} -Wall -pthread -std=c99 -pedantic")
set(CMAKE_C_FLAGS_DEBUG   "-O0 -g -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG -s")
set(CMAKE_CXX_FLAGS         "${CXXFLAGS} -Wall -pthread -std=c++98")
set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG -s")

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
	# must be at start
	${static_link_header}

	${Boost_LIBRARIES}
	# need ssl before crypto
	${OPENSSL_libssl} ${OPENSSL_libcrypto}
	${DEVICE_MAPPER_libdevmapper}

	# i'm not sure about the order here
	${SE_libselinux}
	${SE_libsepol}

	# static linking only; they're all blank for dynamic linking
	${UDEV_libudev}
	${ZLIB_libz}
	${LIBC_librt}
	${LIBC_libdl}
	${LIBC_libpthread}

	# must be at the end
	${static_link_footer}
	)

install(TARGETS fluks
	RUNTIME DESTINATION bin
	)

# recompile cast6.c with -DCAST6_TEST
add_custom_command(OUTPUT cast6_t.o COMMAND ${CMAKE_C_COMPILER} ${CMAKE_SOURCE_DIR}/cast6.c -c -o cast6_t.o -DCAST6_TEST -D_BSD_SOURCE -std=c99 -Wall -pedantic)
add_executable(test-cast6 test/cast6.cpp cast6_t.o)
target_link_libraries(test-cast6 boost_regex)
add_test(test-cast6 ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR}/test ${CMAKE_CURRENT_BINARY_DIR}/test-cast6)

add_executable(test-serpent test/serpent.cpp serpent.cpp)
target_link_libraries(test-serpent boost_regex)
add_test(test-serpent ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR}/test ${CMAKE_CURRENT_BINARY_DIR}/test-serpent)

add_executable(test-twofish test/twofish.cpp twofish.c)
target_link_libraries(test-twofish boost_regex)
add_test(test-twofish ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR}/test ${CMAKE_CURRENT_BINARY_DIR}/test-twofish)

add_executable(test-tiger test/tiger.cpp tiger.c)
add_test(test-tiger ${CMAKE_CURRENT_BINARY_DIR}/test-tiger)
target_link_libraries(test-tiger boost_system)

add_executable(test-whirlpool test/whirlpool.cpp whirlpool.c)
add_test(test-whirlpool ${CMAKE_CURRENT_BINARY_DIR}/test-whirlpool)
target_link_libraries(test-whirlpool boost_system)
