# Copyright (c) 2017-2025 The Bitcoin developers

cmake_minimum_required(VERSION 3.13)
project(univalue)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(UNIVALUE_BUILD_TESTS "Build univalue's unit tests" OFF)

# TODO: Version info
add_library(univalue
	lib/univalue.cpp
	lib/univalue_get.cpp
	lib/univalue_read.cpp
	lib/univalue_write.cpp
)

target_include_directories(univalue
	PUBLIC
		include
	PRIVATE
		lib
)

# Memcoin: tests removed
# if(UNIVALUE_BUILD_TESTS AND ENABLE_TEST)
# ...
# endif()

# Generate lib/univalue_escapes.h
include(NativeExecutable)
add_native_executable(univalue_gen gen/gen.cpp)
native_target_include_directories(univalue_gen PUBLIC include)

# Custom target to regenerate univalue_escapes.h
add_custom_target(generate_univalue_escapes_h
	COMMAND univalue_gen > ${CMAKE_CURRENT_SOURCE_DIR}/lib/univalue_escapes.h
)
