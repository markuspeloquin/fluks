cmake_minimum_required(VERSION 2.8)


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
if(OPENSSL_libssl-NOTFOUND OR OPENSSL_libcrypto-NOTFOUND OR
    OPENSSL_INCLUDE_DIR-NOTFOUND)
	message(FATAL_ERROR "OpenSSL not found")
endif()
message(STATUS "OpenSSL found")

find_library(UTIL_LINUX_libuuid uuid DOC "Util-linux libuuid")
if(UTIL_LINUX_libuuid-NOTFOUND)
	message(FATAL_ERROR "Util-Linux libuuid not found")
endif()
message(STATUS "Util-Linux libuuid found")

find_library(DEVICE_MAPPER_libdevmapper devmapper DOC "Device Mapper (libdevmapper)")
if(DEVICE_MAPPER_libdevmapper-NOTFOUND)
	message(FATAL_ERROR "Device Mapper libdevmapper not found")
endif()
message(STATUS "Device Mapper libdevmapper found")

if(static_linking)
	# required by libdevmapper.a
	find_library(UDEV_libudev udev DOC "libudev")
	if(UDEV_libudev-NOTFOUND)
		message(FATAL_ERROR "libudev not found")
	endif()
	message(STATUS "libudev found")

	# required by libcrypto.a
	find_library(ZLIB_libz z DOC "zlib")
	if(ZLIB_libz-NOTFOUND)
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
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS         "${CXXFLAGS} -Wall -pthread -std=c++98")
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
	# must be at start
	${static_link_header}

	${Boost_LIBRARIES}
	# need ssl before crypto
	${OPENSSL_libssl} ${OPENSSL_libcrypto}
	${UTIL_LINUX_libuuid}
	${DEVICE_MAPPER_libdevmapper}

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
