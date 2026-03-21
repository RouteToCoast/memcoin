// Copyright 2014 BitPay Inc.
// Copyright 2015 Bitcoin Core Developers
// Copyright (c) 2020-2024 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

#define __STDC_FORMAT_MACROS 1

#include "univalue.h"
#include "univalue_detail.h"

#include <array>
#include <cinttypes>
#include <cstdlib>
#include <cmath>
#include <cstdio>
#include <iomanip>
#include <locale>
#include <optional>
#include <sstream>
#include <stdexcept>

const UniValue NullUniValue;

const UniValue& UniValue::Object::operator[](std::string_view key) const noexcept
{
    if (auto found = locate(key)) {
        return *found;
    }
    return NullUniValue;
}

const UniValue& UniValue::Object::operator[](size_type index) const noexcept
{
    if (index < vector.size()) {
        return vector[index].second;
    }
    return NullUniValue;
}

const UniValue* UniValue::Object::locate(std::string_view key) const noexcept {
    for (auto& entry : vector) {
        if (entry.first == key) {
            return &entry.second;
        }
    }
    return nullptr;
}
UniValue* UniValue::Object::locate(std::string_view key) noexcept {
    for (auto& entry : vector) {
        if (entry.first == key) {
            return &entry.second;
        }
    }
    return nullptr;
}

const UniValue& UniValue::Object::at(std::string_view key) const {
    if (auto found = locate(key)) {
        return *found;
    }
    throw std::out_of_range("Key not found in JSON object: " + std::string(key));
}
UniValue& UniValue::Object::at(std::string_view key) {
    if (auto found = locate(key)) {
        return *found;
    }
    throw std::out_of_range("Key not found in JSON object: " + std::string(key));
}

const UniValue& UniValue::Object::at(size_type index) const
{
    if (index < vector.size()) {
        return vector[index].second;
    }
    throw std::out_of_range("Index " + std::to_string(index) + " out of range in JSON object of length " +
                            std::to_string(vector.size()));
}
UniValue& UniValue::Object::at(size_type index)
{
    if (index < vector.size()) {
        return vector[index].second;
    }
    throw std::out_of_range("Index " + std::to_string(index) + " out of range in JSON object of length " +
                            std::to_string(vector.size()));
}

const UniValue& UniValue::Object::front() const noexcept
{
    if (!vector.empty()) {
        return vector.front().second;
    }
    return NullUniValue;
}

const UniValue& UniValue::Object::back() const noexcept
{
    if (!vector.empty()) {
        return vector.back().second;
    }
    return NullUniValue;
}

const UniValue& UniValue::Array::operator[](size_type index) const noexcept
{
    if (index < vector.size()) {
        return vector[index];
    }
    return NullUniValue;
}

const UniValue& UniValue::Array::at(size_type index) const
{
    if (index < vector.size()) {
        return vector[index];
    }
    throw std::out_of_range("Index " + std::to_string(index) + " out of range in JSON array of length " +
                            std::to_string(vector.size()));
}
UniValue& UniValue::Array::at(size_type index)
{
    if (index < vector.size()) {
        return vector[index];
    }
    throw std::out_of_range("Index " + std::to_string(index) + " out of range in JSON array of length " +
                            std::to_string(vector.size()));
}

const UniValue& UniValue::Array::front() const noexcept
{
    if (!vector.empty()) {
        return vector.front();
    }
    return NullUniValue;
}

const UniValue& UniValue::Array::back() const noexcept
{
    if (!vector.empty()) {
        return vector.back();
    }
    return NullUniValue;
}

void UniValue::setType(VType typ, std::optional<std::string> str) noexcept {
    switch (typ) {
        case VNULL: setNull(); break;
        case VFALSE:
        case VTRUE: *this = typ == VTRUE; break;
        case VOBJ: setObject(); break;
        case VARR: setArray(); break;
        case VNUM:
            if (str) var.emplace<Numeric>(std::move(*str));
            else var.emplace<Numeric>();
            break;
        case VSTR:
            if (str) var.emplace<std::string>(std::move(*str));
            else var.emplace<std::string>();
            break;
    }
}

[[nodiscard]] UniValue::VType UniValue::getType() const noexcept {
    using univalue_detail::Overloaded;
    Overloaded visitor{
        [](std::monostate) { return VNULL; },
        [](bool b) { return b ? VTRUE : VFALSE; },
        [](const Numeric &) { return VNUM; },
        [](const std::string &) { return VSTR; },
        [](const Object &) { return VOBJ; },
        [](const Array &) { return VARR; },
    };
    if (!var.valueless_by_exception()) {
        return std::visit(std::move(visitor), var);
    } else {
        // should never happen but here just in case
        return visitor(std::monostate{});
    }
}

static const std::string NullString;

[[nodiscard]] const std::string& UniValue::getValStr() const noexcept {
    if (auto *n = std::get_if<Numeric>(&var)) {
        return n->val;
    } else if (auto *s = std::get_if<std::string>(&var)) {
        return *s;
    }
    return NullString;
}

void UniValue::setNull() noexcept
{
    var.emplace<std::monostate>();
}

void UniValue::operator=(bool val_) noexcept
{
    var.emplace<bool>(val_);
}

UniValue::Object& UniValue::setObject() noexcept
{
    return var.emplace<Object>();
}
UniValue::Object& UniValue::operator=(const Object& object)
{
    if (auto *o = std::get_if<Object>(&var)) {
        return *o = object;
    } else {
        return var.emplace<Object>(object);
    }
}
UniValue::Object& UniValue::operator=(Object&& object) noexcept
{
    if (auto *o = std::get_if<Object>(&var)) {
        return *o = std::move(object);
    } else {
        return var.emplace<Object>(std::move(object));
    }
}

UniValue::Array& UniValue::setArray() noexcept
{
    return var.emplace<Array>();
}
UniValue::Array& UniValue::operator=(const Array& array)
{
    if (auto *a = std::get_if<Array>(&var)) {
        return *a = array;
    } else {
        return var.emplace<Array>(array);
    }
}
UniValue::Array& UniValue::operator=(Array&& array) noexcept
{
    if (auto *a = std::get_if<Array>(&var)) {
        return *a = std::move(array);
    } else {
        return var.emplace<Array>(std::move(array));
    }
}

static std::optional<std::string> validateAndStripNumStr(const char* s)
{
    std::optional<std::string> ret;
    // string must contain a number and no junk at the end
    if (std::string tokenVal, dummy; getJsonToken(tokenVal, s) == JTOK_NUMBER && getJsonToken(dummy, s) == JTOK_NONE) {
        ret.emplace(std::move(tokenVal));
    }
    return ret;
}

void UniValue::setNumStr(const char* val_)
{
    if (auto optStr = validateAndStripNumStr(val_)) {
        var.emplace<Numeric>(std::move(*optStr));
    }
}

template<typename Int64>
void UniValue::setInt64(Int64 val_)
{
    static_assert(std::is_same_v<Int64, int64_t> || std::is_same_v<Int64, uint64_t>,
                  "This function may only be called with either an int64_t or a uint64_t argument.");
    // Begin by setting to null, so that null is assigned if the number cannot be accepted.
    setNull();
    // Longest possible 64-bit integers are "-9223372036854775808" and "18446744073709551615",
    // both of which require 20 visible characters and 1 terminating null,
    // hence buffer size 21.
    constexpr int bufSize = 21;
    std::array<char, bufSize> buf;
    int n = std::snprintf(buf.data(), size_t(bufSize), std::is_signed<Int64>::value ? "%" PRId64 : "%" PRIu64, val_);
    if (n <= 0 || n >= bufSize) // should never happen
        return;
    var.emplace<Numeric>(buf.data(), std::string::size_type(n));
}

void UniValue::operator=(short val_) { setInt64<int64_t>(val_); }
void UniValue::operator=(int val_) { setInt64<int64_t>(val_); }
void UniValue::operator=(long val_) { setInt64<int64_t>(val_); }
void UniValue::operator=(long long val_) { setInt64<int64_t>(val_); }
void UniValue::operator=(unsigned short val_) { setInt64<uint64_t>(val_); }
void UniValue::operator=(unsigned val_) { setInt64<uint64_t>(val_); }
void UniValue::operator=(unsigned long val_) { setInt64<uint64_t>(val_); }
void UniValue::operator=(unsigned long long val_) { setInt64<uint64_t>(val_); }

void UniValue::operator=(double val_)
{
    // Begin by setting to null, so that null is assigned if the number cannot be accepted.
    setNull();
    // Ensure not NaN or inf, which are not representable by the JSON Number type.
    if (!std::isfinite(val_))
        return;
    // For floats and doubles, we can't use snprintf() since the C-locale may be anything,
    // which means the decimal character may be anything. What's more, we can't touch the
    // C-locale since it's a global object and is not thread-safe.
    //
    // So, for doubles we must fall-back to using the (slower) std::ostringstream.
    // See BCHN issue #137.
    std::ostringstream oss;
    oss.imbue(std::locale::classic());
    oss << std::setprecision(16) << val_;
    var.emplace<Numeric>(std::move(oss).str());
}

std::string& UniValue::operator=(std::string_view val_)
{
    return var.emplace<std::string>(val_);
}
std::string& UniValue::operator=(std::string&& val_) noexcept
{
    return var.emplace<std::string>(std::move(val_));
}

const UniValue& UniValue::operator[](std::string_view key) const noexcept
{
    if (auto found = locate(key)) {
        return *found;
    }
    return NullUniValue;
}

const UniValue& UniValue::operator[](size_type index) const noexcept
{
    if (auto *obj = std::get_if<Object>(&var)) {
        return obj->operator[](index);
    } else if (auto *arr = std::get_if<Array>(&var)) {
        return arr->operator[](index);
    }
    return NullUniValue;
}

const UniValue& UniValue::front() const noexcept
{
    if (auto *obj = std::get_if<Object>(&var)) {
        return obj->front();
    } else if (auto *arr = std::get_if<Array>(&var)) {
        return arr->front();
    }
    return NullUniValue;
}

const UniValue& UniValue::back() const noexcept
{
    if (auto *obj = std::get_if<Object>(&var)) {
        return obj->back();
    } else if (auto *arr = std::get_if<Array>(&var)) {
        return arr->back();
    }
    return NullUniValue;
}

const UniValue* UniValue::locate(std::string_view key) const noexcept {
    if (auto *obj = std::get_if<Object>(&var)) {
        return obj->locate(key);
    }
    return nullptr;
}
UniValue* UniValue::locate(std::string_view key) noexcept {
    if (auto *obj = std::get_if<Object>(&var)) {
        return obj->locate(key);
    }
    return nullptr;
}

const UniValue& UniValue::at(std::string_view key) const {
    if (auto *obj = std::get_if<Object>(&var)) {
        return obj->at(key);
    }
    throw std::domain_error(std::string("Cannot look up keys in JSON ") + uvTypeName(type()) +
                            ", expected object with key: " + std::string(key));
}
UniValue& UniValue::at(std::string_view key) {
    if (auto *obj = std::get_if<Object>(&var)) {
        return obj->at(key);
    }
    throw std::domain_error(std::string("Cannot look up keys in JSON ") + uvTypeName(type()) +
                            ", expected object with key: " + std::string(key));
}

const UniValue& UniValue::at(size_type index) const
{
    if (auto *obj = std::get_if<Object>(&var)) {
        return obj->at(index);
    } else if (auto *arr = std::get_if<Array>(&var)) {
        return arr->at(index);
    }
    throw std::domain_error(std::string("Cannot look up indices in JSON ") + uvTypeName(type()) +
                            ", expected array or object larger than " + std::to_string(index) + " elements");
}
UniValue& UniValue::at(size_type index)
{
    if (auto *obj = std::get_if<Object>(&var)) {
        return obj->at(index);
    } else if (auto *arr = std::get_if<Array>(&var)) {
        return arr->at(index);
    }
    throw std::domain_error(std::string("Cannot look up indices in JSON ") + uvTypeName(type()) +
                            ", expected array or object larger than " + std::to_string(index) + " elements");
}

bool UniValue::operator==(const UniValue& other) const noexcept
{
    return var == other.var; // rely on operator== for contained types.
}

const char *uvTypeName(UniValue::VType t) noexcept
{
    switch (t) {
    case UniValue::VNULL: return "null";
    case UniValue::VFALSE: return "false";
    case UniValue::VTRUE: return "true";
    case UniValue::VOBJ: return "object";
    case UniValue::VARR: return "array";
    case UniValue::VNUM: return "number";
    case UniValue::VSTR: return "string";
    // Adding something here? Add it to the other uvTypeName overload below too!
    }

    // not reached
    return nullptr;
}

std::string uvTypeName(int t) {
    std::string result;
    auto appendTypeNameIfTypeIncludes = [&](UniValue::VType type) {
        if (t & type) {
            if (!result.empty()) {
                result += '/';
            }
            result += uvTypeName(type);
        }
    };
    appendTypeNameIfTypeIncludes(UniValue::VNULL);
    appendTypeNameIfTypeIncludes(UniValue::VFALSE);
    appendTypeNameIfTypeIncludes(UniValue::VTRUE);
    appendTypeNameIfTypeIncludes(UniValue::VOBJ);
    appendTypeNameIfTypeIncludes(UniValue::VARR);
    appendTypeNameIfTypeIncludes(UniValue::VNUM);
    appendTypeNameIfTypeIncludes(UniValue::VSTR);
    return result;
}
