cmake_minimum_required(VERSION 3.30)

enable_testing()

option(STATIC "Enable static linking" OFF)

project(fluks LANGUAGES CXX C)

set(Boost_USE_STATIC_LIBS ${STATIC})
set(Boost_USE_MULTITHREADED ON)
find_package(Boost 1.35 REQUIRED COMPONENTS program_options)

set(OPENSSL_USE_STATIC_LIBS ${STATIC})
find_package(OpenSSL)

if(STATIC)
	set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
endif()

find_library(DEVICE_MAPPER_libdevmapper devmapper DOC "libdevmapper (Device Mapper)")
if(${DEVICE_MAPPER_libdevmapper} STREQUAL "DEVICE_MAPPER_libdevmapper-NOTFOUND")
	message(FATAL_ERROR "libdevmapper not found")
endif()
message(STATUS "Device Mapper libdevmapper found")

if(STATIC)
	# revert to old setting
	set(CMAKE_FIND_LIBRARY_SUFFIXES ${_orig_suffixes})
endif()

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

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

target_include_directories(fluks PRIVATE
	${Boost_INCLUDE_DIRS}
	${OPENSSL_INCLUDE_DIR}
)
target_compile_definitions(fluks PRIVATE
	_XOPEN_SOURCE=700
	FLUKS_IS_BIG_ENDIAN=$<STREQUAL:${CMAKE_CXX_BYTE_ORDER},BIG_ENDIAN>
)
target_compile_options(fluks PRIVATE
	$<$<COMPILE_LANGUAGE:C>:  -Wall -Wextra -pedantic>
	$<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra -pedantic -Wno-unused-parameter>
)
target_link_options(fluks PRIVATE
	$<$<CONFIG:Release>:-s> # strip on release
	$<$<BOOL:${STATIC}>:-static>
)
target_link_libraries(fluks
	${Boost_LIBRARIES}
	# need ssl before crypto
	${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY}
	${DEVICE_MAPPER_libdevmapper}
)

install(TARGETS fluks
	RUNTIME DESTINATION sbin
)

# recompile cast6.c with -DCAST6_TEST
add_library(cast6_test_obj OBJECT cast6.c)
target_compile_definitions(cast6_test_obj PRIVATE CAST6_TEST _XOPEN_SOURCE=700)
target_compile_options(cast6_test_obj PRIVATE -Wall -Wextra -pedantic)
set_target_properties(cast6_test_obj PROPERTIES C_STANDARD 23)

add_executable(test-cast6 test/cast6.cpp $<TARGET_OBJECTS:cast6_test_obj>)
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
