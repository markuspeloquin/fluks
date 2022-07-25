cmake_minimum_required(VERSION 3.21)

enable_testing()

set(static_linking FALSE)
#set(static_linking TRUE)

include (TestBigEndian)

project(fluks LANGUAGES CXX C)

set(Boost_FIND_QUIETLY FALSE)
set(Boost_FIND_REQUIRED TRUE)
set(Boost_USE_STATIC_LIBS ${static_linking})
set(Boost_USE_MULTITHREADED TRUE)
if(static_linking)
	set(Boost_USE_STATIC_RUNTIME TRUE)
endif()
find_package(Boost 1.35 COMPONENTS program_options)

if (static_linking)
	set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
find_package(OpenSSL)

if(static_linking)
	set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
endif()

find_library(DEVICE_MAPPER_libdevmapper devmapper DOC "libdevmapper (Device Mapper)")
if(${DEVICE_MAPPER_libdevmapper} STREQUAL "DEVICE_MAPPER_libdevmapper-NOTFOUND")
	message(FATAL_ERROR "libdevmapper not found")
endif()
message(STATUS "Device Mapper libdevmapper found")

# Ubuntu needs these I think?
find_library(SE_libselinux selinux DOC "SE libselinux")
if (${SE_libselinux} STREQUAL "SE_libselinux-NOTFOUND")
	message(STATUS "libselinux not found")
	set(SE_libselinux "")
else()
	message(STATUS "libselinux found")
endif()

find_library(SE_libsepol sepol DOC "SE libsepol")
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
add_definitions(-D_XOPEN_SOURCE=700)
TEST_BIG_ENDIAN(big_endian)
if(big_endian STREQUAL 1)
	add_definitions(-DFLUKS_IS_BIG_ENDIAN=1)
else()
	add_definitions(-DFLUKS_IS_BIG_ENDIAN=0)
endif()
set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic")
set(CMAKE_C_FLAGS_DEBUG   "-O0 -g -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG")
set(CMAKE_CXX_FLAGS         "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter -pedantic")
set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_EXTENSIONS FALSE)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS FALSE)

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
	${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY}
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
	#${static_link_footer}
	)

install(TARGETS fluks
	RUNTIME DESTINATION sbin
	)

# recompile cast6.c with -DCAST6_TEST
add_custom_command(OUTPUT cast6_t.o COMMAND ${CMAKE_C_COMPILER}	-std=c11 -Wall -pedantic -DCAST6_TEST -D_XOPEN_SOURCE=700 ${CMAKE_SOURCE_DIR}/cast6.c -c -o cast6_t.o)
add_executable(test-cast6 test/cast6.cpp cast6_t.o)
target_link_libraries(test-cast6)
add_test(NAME test-cast6 COMMAND test-cast6 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/test)

add_executable(test-serpent test/serpent.cpp serpent.cpp)
target_link_libraries(test-serpent)
add_test(NAME test-serpent COMMAND test-serpent WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/test)

add_executable(test-twofish test/twofish.cpp twofish.c)
target_link_libraries(test-twofish)
add_test(NAME test-twofish COMMAND test-twofish WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/test)

add_executable(test-tiger test/tiger.cpp tiger.c)
target_link_libraries(test-tiger)
add_test(NAME test-tiger COMMAND test-tiger)

add_executable(test-whirlpool test/whirlpool.cpp whirlpool.c)
target_link_libraries(test-whirlpool)
add_test(NAME test-whirlpool COMMAND test-whirlpool)
