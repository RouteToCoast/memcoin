// Copyright (c) 2009-2010 Bit Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Copyright (c) 2025 Memcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/activation.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/blockhash.h>
#include <uint256.h>
#include <util/system.h>

#include <crypto/yesmem/yesmem.h>
#include <atomic>
#include <version.h>
#include <crypto/sha256.h>
bool g_pow_regtest = false;

// Memcoin Yesmem parameters
// Memory per thread = 128 x N x r = 128 x 1,835,008 x 32 ~= 7 GB
static const yesmem_params_t MEMCOIN_YESMEM_PARAMS = {
    YESMEM_1_0,
    1835008,
    32,
    (const uint8_t *)"Memcoin/Yesmem/v1",
    18
};

static std::atomic<const CBlockIndex *> cachedAnchor{nullptr};

void ResetASERTAnchorBlockCache() noexcept {
    cachedAnchor = nullptr;
}

const CBlockIndex *GetASERTAnchorBlockCache() noexcept {
    return cachedAnchor.load();
}

static const CBlockIndex *GetASERTAnchorBlock(const CBlockIndex *const pindex,
                                              const Consensus::Params &params) {
    assert(pindex);

    const CBlockIndex *lastCached = cachedAnchor.load();
    if (lastCached && pindex->GetAncestor(lastCached->nHeight) == lastCached)
        return lastCached;

    const CBlockIndex *anchor = pindex;

    while (anchor->pprev) {
        if (IsAxionEnabled(params, anchor->pskip)) {
            anchor = anchor->pskip;
            continue;
        }
        if (!IsAxionEnabled(params, anchor->pprev)) {
            break;
        }
        anchor = anchor->pprev;
    }

    cachedAnchor = anchor;
    return anchor;
}

static uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
                                         const CBlockHeader *pblock,
                                         const Consensus::Params &params,
                                         const Consensus::Params::ASERTAnchor &anchorParams) noexcept {
    assert(pindexPrev != nullptr);
    assert(pindexPrev->nHeight >= anchorParams.nHeight);

    if (params.fPowAllowMinDifficultyBlocks &&
        (pblock->GetBlockTime() >
         pindexPrev->GetBlockTime() + 2 * params.nPowTargetSpacing)) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    const arith_uint256 powLimit = UintToArith256(params.powLimit);

    /* genesis pprev assert removed */

    const arith_uint256 refBlockTarget = arith_uint256().SetCompact(anchorParams.nBits);

    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - anchorParams.nPrevBlockTime;
    const int nHeightDiff = pindexPrev->nHeight - anchorParams.nHeight;

    arith_uint256 nextTarget = CalculateASERT(refBlockTarget,
                                              params.nPowTargetSpacing,
                                              nTimeDiff,
                                              nHeightDiff,
                                              powLimit,
                                              params.nASERTHalfLife);

    return nextTarget.GetCompact();
}

uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
                                  const CBlockHeader *pblock,
                                  const Consensus::Params &params,
                                  const CBlockIndex *pindexAnchorBlock) noexcept {

    if (params.asertAnchorParams) {
        return GetNextASERTWorkRequired(pindexPrev, pblock, params,
                                        *params.asertAnchorParams);
    }

    assert(pindexAnchorBlock != nullptr);

    const auto anchorTime = pindexAnchorBlock->pprev
                                ? pindexAnchorBlock->pprev->GetBlockTime()
                                : pindexAnchorBlock->GetBlockTime();

    const Consensus::Params::ASERTAnchor anchorParams{
        pindexAnchorBlock->nHeight,
        pindexAnchorBlock->nBits,
        anchorTime
    };

    return GetNextASERTWorkRequired(pindexPrev, pblock, params, anchorParams);
}

arith_uint256 CalculateASERT(const arith_uint256 &refTarget,
                             const int64_t nPowTargetSpacing,
                             const int64_t nTimeDiff,
                             const int64_t nHeightDiff,
                             const arith_uint256 &powLimit,
                             const int64_t nHalfLife) noexcept {

    assert(refTarget > 0 && refTarget <= powLimit);
    /* powLimit>>224 assert removed */
    assert(nHeightDiff >= 0);

    assert( llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ll << (63 - 16)) );
    const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;

    static_assert(int64_t(-1) >> 1 == int64_t(-1),
                  "ASERT algorithm needs arithmetic shift support");

    int64_t shifts = exponent >> 16;
    const auto frac = uint16_t(exponent);
    assert(exponent == (shifts * 65536) + frac);

    const uint32_t factor = 65536 + ((
        + 195766423245049ull * frac
        + 971821376ull * frac * frac
        + 5127ull * frac * frac * frac
        + (1ull << 47)
        ) >> 48);

    arith_uint256 nextTarget = (refTarget >> 16) * factor;

        if (shifts <= 0) {
        nextTarget >>= -shifts;
    } else {
        const auto nextTargetShifted = nextTarget << shifts;
        if ((nextTargetShifted >> shifts) != nextTarget) {
            nextTarget = powLimit;
        } else {
            nextTarget = nextTargetShifted;
        }
    }

    if (nextTarget == 0) {
        nextTarget = arith_uint256(1);
    } else if (nextTarget > powLimit) {
        nextTarget = powLimit;
    }

    return nextTarget;
}

uint32_t GetNextWorkRequired(const CBlockIndex *pindexPrev,
                             const CBlockHeader *pblock,
                             const Consensus::Params &params) {
    assert(pindexPrev != nullptr);
    if (params.fPowNoRetargeting) {
        return pindexPrev->nBits;
    }
    // Memcoin: ASERT only, always enabled from genesis
    assert(IsAxionEnabled(params, pindexPrev));
    const CBlockIndex *panchorBlock = nullptr;
    if (!params.asertAnchorParams) {
        panchorBlock = GetASERTAnchorBlock(pindexPrev, params);
    }
    return GetNextASERTWorkRequired(pindexPrev, pblock, params, panchorBlock);
}

uint32_t CalculateNextWorkRequired(const CBlockIndex *pindexPrev,
                                   int64_t nFirstBlockTime,
                                   const Consensus::Params &params) {
    if (params.fPowNoRetargeting) {
        return pindexPrev->nBits;
    }

    int64_t nActualTimespan = pindexPrev->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan / 4) {
        nActualTimespan = params.nPowTargetTimespan / 4;
    }

    if (nActualTimespan > params.nPowTargetTimespan * 4) {
        nActualTimespan = params.nPowTargetTimespan * 4;
    }

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    return bnNew.GetCompact();
}

// Memcoin: compute Yesmem hash of a block header
// Fixed 80-byte manual serialization — independent of CDataStream and PROTOCOL_VERSION
uint256 GetPoWHash(const CBlockHeader &header) {
    uint256 result;
    // Bitcoin block header is always exactly 80 bytes:
    // nVersion(4) + hashPrevBlock(32) + hashMerkleRoot(32) + nTime(4) + nBits(4) + nNonce(4)
    uint8_t buf[80];
    uint32_t ver   = htole32((uint32_t)header.nVersion);
    uint32_t t     = htole32(header.nTime);
    uint32_t bits  = htole32(header.nBits);
    uint32_t nonce = htole32(header.nNonce);
    memcpy(buf +  0, &ver,                            4);
    memcpy(buf +  4, header.hashPrevBlock.begin(),   32);
    memcpy(buf + 36, header.hashMerkleRoot.begin(),  32);
    memcpy(buf + 68, &t,                              4);
    memcpy(buf + 72, &bits,                           4);
    memcpy(buf + 76, &nonce,                          4);
    if (g_pow_regtest) {
        uint8_t tmp[32];
        CSHA256().Write(buf, 80).Finalize(tmp);
        CSHA256().Write(tmp, 32).Finalize(result.begin());
        return result;
    }
    yesmem_local_t local;
    yesmem_init_local(&local);
    if (yesmem(&local, buf, 80, &MEMCOIN_YESMEM_PARAMS,
               (yesmem_binary_t *)result.begin()) != 0) {
        LogPrintf("ERROR: yesmem failed (out of memory — requires ~7 GB per thread)\n");
        memset(result.begin(), 0xFF, 32);
    }
    yesmem_free_local(&local);
    return result;
}

// WARNING: Legacy function — accepts SHA256d hash, NOT Yesmem hash.
// Do NOT use for block validation. Use CheckProofOfWorkWithHeader() instead.
// Kept only for API compatibility.
bool CheckProofOfWork(const BlockHash &hash,
                      uint32_t nBits,
                      const Consensus::Params &params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative || bnTarget == 0 || fOverflow ||
        bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    if (UintToArith256(hash) > bnTarget) {
        return false;
    }

    return true;
}

// Memcoin: full Yesmem PoW verification.
// Called from CheckBlockHeader() in validation.cpp.
bool CheckProofOfWorkWithHeader(const CBlockHeader &header,
                                uint32_t nBits,
                                const Consensus::Params &params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative || bnTarget == 0 || fOverflow ||
        bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    uint256 powHash = GetPoWHash(header);

    if (UintToArith256(powHash) > bnTarget) {
        return false;
    }

    return true;
}

static arith_uint256 ComputeTarget(const CBlockIndex *pindexFirst,
                                   const CBlockIndex *pindexLast,
                                   const Consensus::Params &params) {
    assert(pindexLast->nHeight > pindexFirst->nHeight);

    arith_uint256 work = pindexLast->nChainWork - pindexFirst->nChainWork;
    work *= params.nPowTargetSpacing;

    int64_t nActualTimespan =
        int64_t(pindexLast->nTime) - int64_t(pindexFirst->nTime);
    if (nActualTimespan > 288 * params.nPowTargetSpacing) {
        nActualTimespan = 288 * params.nPowTargetSpacing;
    } else if (nActualTimespan < 72 * params.nPowTargetSpacing) {
        nActualTimespan = 72 * params.nPowTargetSpacing;
    }

    work /= nActualTimespan;

    return (-work) / work;
}

static const CBlockIndex *GetSuitableBlock(const CBlockIndex *pindex) {
    assert(pindex->nHeight >= 3);

    const CBlockIndex *blocks[3];
    blocks[2] = pindex;
    blocks[1] = pindex->pprev;
    blocks[0] = blocks[1]->pprev;

    if (blocks[0]->nTime > blocks[2]->nTime) {
        std::swap(blocks[0], blocks[2]);
    }

    if (blocks[0]->nTime > blocks[1]->nTime) {
        std::swap(blocks[0], blocks[1]);
    }

    if (blocks[1]->nTime > blocks[2]->nTime) {
        std::swap(blocks[1], blocks[2]);
    }

    return blocks[1];
}

