#!/usr/bin/env python3
# Copyright (c) 2020-2025 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Allow to easily create a custom command that uses dep file.
# depfile are a ninja only feature and a hard fail using other generators.

# Define how DEPFILEs are treated (Policy CMP0116, introduced in CMake 3.20)
if(POLICY CMP0116)
	cmake_policy(SET CMP0116 NEW)
endif()

function(add_custom_command_with_depfile)
	cmake_parse_arguments("" "" "DEPFILE" "" ${ARGN})

	if(_DEPFILE AND "${CMAKE_GENERATOR}" MATCHES "Ninja")
		set(_dep_file_arg DEPFILE "${_DEPFILE}")
	endif()

	add_custom_command(${_UNPARSED_ARGUMENTS} ${_dep_file_arg})
endfunction()
