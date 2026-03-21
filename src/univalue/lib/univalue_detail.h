// Copyright (c) 2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

#ifndef UNIVALUE_DETAIL_H__
#define UNIVALUE_DETAIL_H__

namespace univalue_detail {
//! Overloaded helper for std::visit. This helper and std::visit in general are
//! useful to write code that switches on a variant type. Unlike if/else-if and
//! switch/case statements, std::visit will trigger compile errors if there are
//! unhandled cases.
//!
//! Implementation comes from and example usage can be found at
//! https://en.cppreference.com/w/cpp/utility/variant/visit#Example
template<class... Ts> struct Overloaded : Ts... { using Ts::operator()...; };
//! Explicit deduction guide (not needed as of C++20)
template<class... Ts> Overloaded(Ts...) -> Overloaded<Ts...>;
} // univalue_detail

#endif // UNIVALUE_DETAIL_H__
