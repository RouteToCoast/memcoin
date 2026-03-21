// Copyright (c) 2022 The Bitcoin Core developers
// Copyright (c) 2024-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/check.h>

#include <clientversion.h>
#include <tinyformat.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

std::string StrFormatInternalBug(std::string_view msg, std::string_view file, int line, std::string_view func) {
    return strprintf("Internal bug detected: %s\n%s:%d (%s)\n"
                     "%s %s\n"
                     "Please report this issue to the developers.\n",
                     msg, file, line, func, CLIENT_NAME, FormatFullVersion());
}

NonFatalCheckError::NonFatalCheckError(std::string_view msg, std::string_view file, int line, std::string_view func)
    : std::runtime_error{StrFormatInternalBug(msg, file, line, func)}
{
}

[[noreturn]]
void assertion_fail(std::string_view file, int line, std::string_view func, std::string_view assertion) {
    const auto str = strprintf("%s:%s %s: Assertion `%s' failed.\n", file, line, func, assertion);
    std::fwrite(str.data(), 1, str.size(), stderr);
    std::abort();
}
