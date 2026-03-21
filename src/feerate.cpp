// Copyright (c) 2009-2010 Bit Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <feerate.h>

#include <amount.h>
#include <tinyformat.h>

CFeeRate::CFeeRate(const Amount nFeePaid, size_t nBytes_) {
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    if (nSize > 0) {
        nBitsPerK = 1000 * nFeePaid / nSize;
    } else {
        nBitsPerK = Amount::zero();
    }
}

template <bool ceil>
static Amount GetFee(size_t nBytes_, Amount nBitsPerK) {
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    // Ensure fee is rounded up when truncated if ceil is true.
    Amount nFee = Amount::zero();
    if (ceil) {
        nFee = Amount(nSize * nBitsPerK % 1000 > Amount::zero()
                          ? nSize * nBitsPerK / 1000 + BIT
                          : nSize * nBitsPerK / 1000);
    } else {
        nFee = nSize * nBitsPerK / 1000;
    }

    if (nFee == Amount::zero() && nSize != 0) {
        if (nBitsPerK > Amount::zero()) {
            nFee = BIT;
        }
        if (nBitsPerK < Amount::zero()) {
            nFee = -BIT;
        }
    }

    return nFee;
}

Amount CFeeRate::GetFee(size_t nBytes) const {
    return ::GetFee<false>(nBytes, nBitsPerK);
}

Amount CFeeRate::GetFeeCeiling(size_t nBytes) const {
    return ::GetFee<true>(nBytes, nBitsPerK);
}

std::string CFeeRate::ToString() const {
    return strprintf("%d.%08d %s/kB", nBitsPerK / COIN,
                     (nBitsPerK % COIN) / BIT, CURRENCY_UNIT);
}
