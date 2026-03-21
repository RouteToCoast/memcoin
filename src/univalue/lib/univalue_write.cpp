// Copyright 2014 BitPay Inc.
// Copyright (c) 2020-2024 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

#include "univalue.h"
#include "univalue_detail.h"
#include "univalue_escapes.h"

#include <string_view>

/* static */
void UniValue::jsonEscape(Stream & ss, std::string_view inS)
{
    for (const auto ch : inS) {
        const char * const escStr = escapes[uint8_t(ch)];

        if (escStr)
            ss << escStr;
        else
            ss.put(ch);
    }
}

/* static */
inline void UniValue::startNewLine(Stream & ss, const unsigned int prettyIndent, const unsigned int indentLevel)
{
    if (prettyIndent) {
        ss.put('\n');
        ss.put(' ', indentLevel);
    }
}

/* static */
void UniValue::stringify(Stream& ss, const UniValue& value, const unsigned int prettyIndent, const unsigned int indentLevel)
{
    using namespace std::string_view_literals;
    using univalue_detail::Overloaded;
    Overloaded visitor{
        [&](std::monostate) { ss << "null"sv; },
        [&](bool b) { ss << (b ? "true"sv : "false"sv); },
        [&](const Object &entries) { stringify(ss, entries, prettyIndent, indentLevel); },
        [&](const Array &values) { stringify(ss, values, prettyIndent, indentLevel); },
        [&](const Numeric &num) { ss << num.val; },
        [&](const std::string &str) { stringify(ss, str, prettyIndent, indentLevel); },
    };
    if (!value.var.valueless_by_exception()) {
        std::visit(std::move(visitor), value.var);
    } else {
        // should never happen but here just in case
        visitor(std::monostate{});
    }
}

/* static */
void UniValue::stringify(Stream & ss, const UniValue::Object& object, const unsigned int prettyIndent, const unsigned int indentLevel)
{
    ss.put('{');
    if (!object.empty()) {
        const unsigned int internalIndentLevel = indentLevel + prettyIndent;
        for (auto entry = object.begin(), end = object.end();;) {
            startNewLine(ss, prettyIndent, internalIndentLevel);
            ss.put('"');
            jsonEscape(ss, entry->first);
            ss << "\":";
            if (prettyIndent) {
                ss.put(' ');
            }
            stringify(ss, entry->second, prettyIndent, internalIndentLevel);
            if (++entry == end) {
                break;
            }
            ss.put(',');
        }
    }
    startNewLine(ss, prettyIndent, indentLevel);
    ss.put('}');
}

/* static */
void UniValue::stringify(Stream & ss, const UniValue::Array& array, const unsigned int prettyIndent, const unsigned int indentLevel)
{
    ss.put('[');
    if (!array.empty()) {
        const unsigned int internalIndentLevel = indentLevel + prettyIndent;
        for (auto value = array.begin(), end = array.end();;) {
            startNewLine(ss, prettyIndent, internalIndentLevel);
            stringify(ss, *value, prettyIndent, internalIndentLevel);
            if (++value == end) {
                break;
            }
            ss.put(',');
        }
    }
    startNewLine(ss, prettyIndent, indentLevel);
    ss.put(']');
}

/* static */
void UniValue::stringify(Stream& ss, std::string_view string, const unsigned int prettyIndent [[maybe_unused]],
                         const unsigned int indentLevel [[maybe_unused]])
{
    ss.put('"');
    jsonEscape(ss, string);
    ss.put('"');
}
