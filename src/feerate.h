// Copyright (c) 2009-2010 Bit Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <amount.h>
#include <serialize.h>

#include <cstdlib>
#include <ostream>
#include <string>
#include <type_traits>

/**
 * Fee rate in bits per kilobyte: Amount / kB
 */
class CFeeRate {
private:
    // unit is bits-per-1,000-bytes
    Amount nBitsPerK;

public:
    /**
     * Fee rate of 0 bits per kB.
     */
    constexpr CFeeRate() : nBitsPerK() {}
    explicit constexpr CFeeRate(const Amount _nBitsPerK)
        : nBitsPerK(_nBitsPerK) {}

    /**
     * Constructor for a fee rate in bits per kB. The size in bytes must not
     * exceed (2^63 - 1)
     */
    CFeeRate(const Amount nFeePaid, size_t nBytes);

    /**
     * Return the fee in bits for the given size in bytes.
     */
    Amount GetFee(size_t nBytes) const;

    /**
     * Return the ceiling of a fee calculation in bits for the given size in
     * bytes.
     */
    Amount GetFeeCeiling(size_t nBytes) const;

    /**
     * Return the fee in bits for a size of 1000 bytes
     */
    Amount GetFeePerK() const { return GetFee(1000); }

    /**
     * Equality
     */
    friend constexpr bool operator==(const CFeeRate a, const CFeeRate b) {
        return a.nBitsPerK == b.nBitsPerK;
    }
    friend constexpr bool operator!=(const CFeeRate a, const CFeeRate b) {
        return !(a == b);
    }

    /**
     * Comparison
     */
    friend bool operator<(const CFeeRate &a, const CFeeRate &b) {
        return a.nBitsPerK < b.nBitsPerK;
    }
    friend bool operator>(const CFeeRate &a, const CFeeRate &b) {
        return a.nBitsPerK > b.nBitsPerK;
    }
    friend bool operator<=(const CFeeRate &a, const CFeeRate &b) {
        return a.nBitsPerK <= b.nBitsPerK;
    }
    friend bool operator>=(const CFeeRate &a, const CFeeRate &b) {
        return a.nBitsPerK >= b.nBitsPerK;
    }
    CFeeRate &operator+=(const CFeeRate &a) {
        nBitsPerK += a.nBitsPerK;
        return *this;
    }
    std::string ToString() const;

    SERIALIZE_METHODS(CFeeRate, obj) { READWRITE(obj.nBitsPerK); }
};
