// Copyright (c) 2009-2010 Bit Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2020-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes
// only local node policy logic

#include <policy/policy.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <script/vm_limits.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validation.h>

Amount GetDustThreshold(const CTxOut &txout, const CFeeRate &dustRelayFeeIn) {
    /**
     * "Dust" is defined in terms of dustRelayFee, which has units
     * bits-per-kilobyte. If you'd pay more than 1/3 in fees to spend
     * something, then we consider it dust.  A typical spendable txout is 34
     * bytes big, and will need a CTxIn of at least 148 bytes to spend: so dust
     * is a spendable txout less than 546*dustRelayFee/1000 (in bits).
     */
    if (txout.scriptPubKey.IsUnspendable()) {
        return Amount::zero();
    }

    size_t nSize = GetSerializeSize(txout);

    // the 148 mentioned above
    nSize += (32 + 4 + 1 + 107 + 4);

    return 3 * dustRelayFeeIn.GetFee(nSize);
    }

    bool IsDust(const CTxOut &txout, const CFeeRate &dustRelayFeeIn) {
    return (txout.nValue < GetDustThreshold(txout, dustRelayFeeIn));
    }

    bool IsStandard(const CScript &scriptPubKey, txnouttype &whichType, uint32_t flags) {
    std::vector<std::vector<uint8_t>> vSolutions;
    whichType = Solver(scriptPubKey, vSolutions, flags);
    if (whichType == TX_NONSTANDARD) {
        // Memcoin: CLTV+P2PKH
        CScript::const_iterator pc = scriptPubKey.begin();
        opcodetype opcode;
        std::vector<uint8_t> data;
        if (!scriptPubKey.GetOp(pc, opcode, data)) return false;
        if (data.empty() || data.size() > 5) return false;
        if (!scriptPubKey.GetOp(pc, opcode, data)) return false;
        if (opcode != OP_CHECKLOCKTIMEVERIFY) return false;
        if (!scriptPubKey.GetOp(pc, opcode, data)) return false;
        if (opcode != OP_DROP) return false;
        if (!scriptPubKey.GetOp(pc, opcode, data)) return false;
        if (opcode != OP_DUP) return false;
        if (!scriptPubKey.GetOp(pc, opcode, data)) return false;
        if (opcode != OP_HASH160) return false;
        if (!scriptPubKey.GetOp(pc, opcode, data)) return false;
        if (data.size() != 20) return false;
        if (!scriptPubKey.GetOp(pc, opcode, data)) return false;
        if (opcode != OP_EQUALVERIFY) return false;
        if (!scriptPubKey.GetOp(pc, opcode, data)) return false;
        if (opcode != OP_CHECKSIG) return false;
        if (pc != scriptPubKey.end()) return false;
        whichType = TX_PUBKEYHASH;
        return true;
    }
    // Memcoin: only P2PKH (including CLTV+P2PKH) is standard
    return (whichType == TX_PUBKEYHASH);
}

bool IsStandardTx(const CTransaction &tx, std::string &reason, uint32_t flags) {
    // Note that this standardness check may be safely removed after Upgrade9 activates since at that point nVersion
    // as 1 or 2 will be enforced via consensus, rather than relay policy.
    if (tx.nVersion > CTransaction::MAX_STANDARD_VERSION || tx.nVersion < CTransaction::MIN_STANDARD_VERSION) {
        reason = "version";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
    uint32_t sz = tx.GetTotalSize();
    if (sz > MAX_STANDARD_TX_SIZE) {
        reason = "tx-size";
        return false;
    }

    // Pre-upgrade 12, we always had the standardness rule that scriptSigs could not exceed 1,650 bytes.
    // Post-upgrade 12, we relax this limit to the maximum script size (10,000 bytes).
    const size_t maxScriptSigSize = !(flags & SCRIPT_ENABLE_MAY2026) ? MAX_TX_IN_SCRIPT_SIG_SIZE_LEGACY
                                                                     : MAX_SCRIPT_SIZE;

    for (const CTxIn &txin : tx.vin) {
        if (txin.scriptSig.size() > maxScriptSigSize) {
            // Note: after upgrade 12 is activated and checkpointed, this standardness check can be eliminated entirely
            // since the script interpreter itself enforces a 10KB limit on scriptSig (interpreter.cpp; EvalScriptImpl).
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
    }

    txnouttype whichType;
    for (const CTxOut &txout : tx.vout) {
        if (!(flags & SCRIPT_ENABLE_TOKENS) && txout.tokenDataPtr) {
            // Pre-token activation:
            // Txn has token data that actually deserialized as token data, but tokens are not activated yet.
            // Treat the txn as non-standard to keep old pre-activation mempool behavior (which would have disallowed
            // these as non-standard).
            reason = "txn-tokens-before-activation";
            return false;
        }

        if (!::IsStandard(txout.scriptPubKey, whichType, flags)) {
            reason = "scriptpubkey";
            return false;
        }

        if (whichType == TX_NULL_DATA) {
        } else if (IsDust(txout, ::dustRelayFee)) {
            // Memcoin: skip dust check for CLTV outputs (TX1 denominations)
            auto isCLTV = [](const CScript &s) -> bool {
                CScript::const_iterator pc = s.begin();
                opcodetype op; std::vector<uint8_t> vch;
                if (!s.GetOp(pc, op, vch) || vch.empty()) return false;
                if (!s.GetOp(pc, op, vch)) return false;
                if (op != OP_CHECKLOCKTIMEVERIFY) return false;
                if (!s.GetOp(pc, op, vch)) return false;
                if (op != OP_DROP) return false;
                if (!s.GetOp(pc, op, vch)) return false;
                if (op != OP_DUP) return false;
                if (!s.GetOp(pc, op, vch)) return false;
                if (op != OP_HASH160) return false;
                if (!s.GetOp(pc, op, vch)) return false;
                if (vch.size() != 20) return false;
                if (!s.GetOp(pc, op, vch)) return false;
                if (op != OP_EQUALVERIFY) return false;
                if (!s.GetOp(pc, op, vch)) return false;
                if (op != OP_CHECKSIG) return false;
                return pc == s.end();
            };
            if (!isCLTV(txout.scriptPubKey)) {
                reason = "dust";
                return false;
            }
        }
    }


    return true;
}

/**
 * Check transaction inputs to mitigate two
 * potential denial-of-service attacks:
 *
 * 1. scriptSigs with extra data stuffed into them,
 *    not consumed by scriptPubKey
 * 2. Scripts with a crazy number of expensive
 *    CHECKSIG/CHECKMULTISIG operations
 */
bool AreInputsStandard(const CTransaction &tx, const CCoinsViewCache &mapInputs,
                       uint32_t flags) {
    if (tx.IsCoinBase()) {
        // Coinbases don't use vin normally.
        return true;
    }

    for (const CTxIn &in : tx.vin) {
        const CTxOut &prev = mapInputs.GetOutputFor(in);

        if (!(flags & SCRIPT_ENABLE_TOKENS) && prev.tokenDataPtr) {
            // Input happened to have serialized token data but tokens are not activated yet. Reject this txn as
            // non-standard -- note this input would fail to be spent anyway later on in the pipeline, but we prefer
            // to tell the caller that the txn is non-standard so as to to emulate the behavior of unupgraded nodes.
            return false;
        }

        std::vector<std::vector<uint8_t>> vSolutions;
        txnouttype whichType = Solver(prev.scriptPubKey, vSolutions, flags);
        if (whichType == TX_NONSTANDARD) {
            // Memcoin: allow CLTV+P2PKH inputs (TX2)
            const CScript &s = prev.scriptPubKey;
            CScript::const_iterator pc = s.begin();
            opcodetype op; std::vector<uint8_t> vch;
            if (!s.GetOp(pc, op, vch) || vch.empty()) return false;
            if (!s.GetOp(pc, op, vch) || op != OP_CHECKLOCKTIMEVERIFY) return false;
            // valid CLTV+P2PKH input, allow
        }
    }

    return true;
}

CFeeRate dustRelayFee = CFeeRate(DUST_RELAY_TX_FEE);
uint32_t nBytesPerSigCheck = DEFAULT_BYTES_PER_SIGCHECK;

int64_t GetVirtualTransactionSize(int64_t nSize, int64_t nSigChecks,
                                  unsigned int bytes_per_sigcheck) {
    return std::max(nSize, nSigChecks * bytes_per_sigcheck);
}

int64_t GetVirtualTransactionSize(const CTransaction &tx, int64_t nSigChecks,
                                  unsigned int bytes_per_sigcheck) {
    return GetVirtualTransactionSize(::GetSerializeSize(tx, PROTOCOL_VERSION),
                                     nSigChecks, bytes_per_sigcheck);
}

int64_t GetVirtualTransactionInputSize(const CTxIn &txin, int64_t nSigChecks,
                                       unsigned int bytes_per_sigcheck) {
    return GetVirtualTransactionSize(::GetSerializeSize(txin, PROTOCOL_VERSION),
                                     nSigChecks, bytes_per_sigcheck);
}