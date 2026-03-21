// Copyright (c) 2009-2010 Bit Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2020-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sign.h>

#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <uint256.h>

TransactionSignatureCreator::TransactionSignatureCreator(const ScriptExecutionContext &contextIn,
                                                         SigHashType sigHashTypeIn)
    : context(contextIn), sigHashType(sigHashTypeIn), checker(contextIn)
{}

bool TransactionSignatureCreator::CreateSig(const SigningProvider &provider, std::vector<uint8_t> &vchSig,
                                            const CKeyID &address, const CScript &scriptCode,
                                            uint32_t scriptFlags) const {
    CKey key;
    if (!provider.GetKey(address, key)) {
        return false;
    }

    const auto & [hash, bytesHashed] = SignatureHash(scriptCode, context, sigHashType, nullptr, scriptFlags);
    if (!key.SignECDSA(hash, vchSig)) {
        return false;
    }

    vchSig.push_back(uint8_t(sigHashType.getRawSigHashType()));
    return true;
}

static bool CreateSig(const BaseSignatureCreator &creator,
                      SignatureData &sigdata, const SigningProvider &provider,
                      std::vector<uint8_t> &sig_out, const CPubKey &pubkey,
                      const CScript &scriptcode, uint32_t scriptFlags) {
    CKeyID keyid = pubkey.GetID();
    const auto it = sigdata.signatures.lower_bound(keyid);
    if (it != sigdata.signatures.end() && it->first == keyid) {
        sig_out = it->second.second;
        return true;
    }
    KeyOriginInfo info;
    if (provider.GetKeyOrigin(keyid, info)) {
        sigdata.misc_pubkeys.emplace(std::piecewise_construct,
                                     std::forward_as_tuple(keyid),
                                     std::forward_as_tuple(pubkey, std::move(info)));
    }
    if (creator.CreateSig(provider, sig_out, keyid, scriptcode, scriptFlags)) {
        sigdata.signatures.emplace_hint(it,
                                        std::piecewise_construct,
                                        std::forward_as_tuple(keyid),
                                        std::forward_as_tuple(pubkey, sig_out));
        return true;
    }
    return false;
}

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey
 * can't be signed), unless whichTypeRet is TX_SCRIPTHASH, in which case
 * scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */

// Memcoin: detect CLTV P2PKH scriptPubKey
// Pattern: <locktime> OP_CLTV OP_DROP OP_DUP OP_HASH160 <20-byte-pkh> OP_EQUALVERIFY OP_CHECKSIG
static bool ExtractCLTVPubKeyHash(const CScript &scriptPubKey,
                                   std::vector<uint8_t> &pkhOut) {
    const uint8_t OP_CLTV        = 0xb1;
    const uint8_t OP_DROP        = 0x75;
    const uint8_t OP_DUP         = 0x76;
    const uint8_t OP_HASH160     = 0xa9;
    const uint8_t OP_EQUALVERIFY = 0x88;
    const uint8_t OP_CHECKSIG    = 0xac;
    const uint8_t PUSH_20        = 0x14;
    const size_t TAIL_LEN = 27;

    const uint8_t *data = scriptPubKey.data();
    const size_t   len  = scriptPubKey.size();
    if (len < TAIL_LEN + 1) return false;

    uint8_t first = data[0];
    size_t ltEnd;
    if (first >= 0x51 && first <= 0x60) {
        ltEnd = 1;
    } else if (first >= 0x01 && first <= 0x04) {
        ltEnd = 1 + first;
        if (ltEnd > len) return false;
    } else {
        return false;
    }

    if (ltEnd + TAIL_LEN != len) return false;
    const uint8_t *p = data + ltEnd;
    if (p[0] != OP_CLTV)         return false;
    if (p[1] != OP_DROP)         return false;
    if (p[2] != OP_DUP)          return false;
    if (p[3] != OP_HASH160)      return false;
    if (p[4] != PUSH_20)         return false;
    if (p[25] != OP_EQUALVERIFY) return false;
    if (p[26] != OP_CHECKSIG)    return false;

    pkhOut.assign(p + 5, p + 25);
    return true;
}

static bool SignStep(const SigningProvider &provider,
                     const BaseSignatureCreator &creator,
                     const CScript &scriptPubKey, std::vector<valtype> &ret,
                     txnouttype &whichTypeRet, SignatureData &sigdata, uint32_t scriptFlags) {
    CScript scriptRet;
    ret.clear();
    std::vector<uint8_t> sig;

    std::vector<valtype> vSolutions;
    whichTypeRet = Solver(scriptPubKey, vSolutions, scriptFlags);

    // Memcoin: CLTV P2PKH — scriptSig identical to plain P2PKH (<sig> <pubkey>)
    {
        std::vector<uint8_t> pkh;
        if (ExtractCLTVPubKeyHash(scriptPubKey, pkh)) {
            CKeyID keyID = CKeyID(uint160(pkh));
            CPubKey pubkey;
            if (!provider.GetPubKey(keyID, pubkey)) { return false; }
            if (!CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, scriptFlags)) {
                return false;
            }
            ret.push_back(std::move(sig));
            ret.push_back(ToByteVector(pubkey));
            return true;
        }
    }
    switch (whichTypeRet) {
        case TX_NONSTANDARD:
        case TX_NULL_DATA:
        case TX_SCRIPT:
            return false;
        case TX_PUBKEY:
            if (!CreateSig(creator, sigdata, provider, sig, CPubKey(vSolutions[0]), scriptPubKey, scriptFlags)) {
                return false;
            }
            ret.push_back(std::move(sig));
            return true;
        case TX_PUBKEYHASH: {
            CKeyID keyID = CKeyID(uint160(vSolutions[0]));
            CPubKey pubkey;
            if (!provider.GetPubKey(keyID, pubkey)) {
                return false;
            }
            if (!CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, scriptFlags)) {
                return false;
            }
            ret.push_back(std::move(sig));
            ret.push_back(ToByteVector(pubkey));
            return true;
        }
        case TX_MULTISIG: {
            size_t required = vSolutions.front()[0];
            // workaround CHECKMULTISIG bug
            ret.push_back(valtype());
            for (size_t i = 1; i < vSolutions.size() - 1; ++i) {
                CPubKey pubkey = CPubKey(vSolutions[i]);
                if (ret.size() < required + 1 &&
                    CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, scriptFlags)) {
                    ret.push_back(std::move(sig));
                }
            }
            bool ok = ret.size() == required + 1;
            for (size_t i = 0; i + ret.size() < required + 1; ++i) {
                ret.push_back(valtype());
            }
            return ok;
        }
        default:
            return false;
    }
}

static CScript PushAll(const std::vector<valtype> &values) {
    CScript result;
    for (const valtype &v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else {
            result << v;
        }
    }

    return result;
}

bool ProduceSignature(const SigningProvider &provider,
                      const BaseSignatureCreator &creator,
                      const CScript &fromPubKey, SignatureData &sigdata, uint32_t scriptFlags) {
    if (sigdata.complete) {
        return true;
    }

    std::vector<valtype> result;
    txnouttype whichType;
    bool solved = SignStep(provider, creator, fromPubKey, result, whichType, sigdata, scriptFlags);

    // Memcoin: P2SH disabled - subscript block removed

    sigdata.scriptSig = PushAll(result);

    // Test solution
    sigdata.complete = solved && VerifyScript(sigdata.scriptSig, fromPubKey, scriptFlags, creator.Checker());

    return sigdata.complete;
}

class SignatureExtractorChecker final : public BaseSignatureChecker {
private:
    SignatureData &sigdata;
    BaseSignatureChecker &checker;

public:
    SignatureExtractorChecker(SignatureData &sigdata_,
                              BaseSignatureChecker &checker_)
        : sigdata(sigdata_), checker(checker_) {}
    bool CheckSig(const ByteView &scriptSig,
                  const std::vector<uint8_t> &vchPubKey,
                  const ByteView &scriptCode, uint32_t flags, size_t *pBytesHashed) const override;
    const ScriptExecutionContext *GetContext() const override { return checker.GetContext(); }
};

bool SignatureExtractorChecker::CheckSig(const ByteView &scriptSig,
                                         const std::vector<uint8_t> &vchPubKey,
                                         const ByteView &scriptCode,
                                         uint32_t flags, size_t *pBytesHashed) const {
    if (checker.CheckSig(scriptSig, vchPubKey, scriptCode, flags, pBytesHashed)) {
        CPubKey pubkey(vchPubKey);
        std::vector<uint8_t> vchSig(scriptSig.begin(), scriptSig.end());
        sigdata.signatures.emplace(std::piecewise_construct,
                                   std::forward_as_tuple(pubkey.GetID()),
                                   std::forward_as_tuple(std::move(pubkey), std::move(vchSig)));
        return true;
    }
    return false;
}

namespace {
struct Stacks {
    std::vector<valtype> script;

    Stacks() = delete;
    Stacks(const Stacks &) = delete;

    Stacks(const SignatureData &data, ScriptExecutionContextOpt const& context) {
        if (data.scriptSig.IsPushOnly()) {
            EvalScript(script, data.scriptSig, SCRIPT_VERIFY_NONE, ContextOptSignatureChecker(context));
        }
    }
};
} // namespace

// Extracts signatures and scripts from incomplete scriptSigs. Please do not
// extend this, use PSBT instead
SignatureData DataFromTransaction(const ScriptExecutionContext &context, const uint32_t scriptFlags) {
    SignatureData data;
    const auto &tx = context.tx();
    const auto nIn = context.inputIndex();
    assert(tx.vin().size() > nIn);
    data.scriptSig = tx.vin()[nIn].scriptSig;
    Stacks stack(data, context);

    // Get signatures
    TransactionSignatureChecker tx_checker(context);
    SignatureExtractorChecker extractor_checker(data, tx_checker);

    const CTxOut &txout = context.coin().GetTxOut();
    if (VerifyScript(data.scriptSig, txout.scriptPubKey, scriptFlags, extractor_checker)) {
        data.complete = true;
        return data;
    }

    // Get scripts
    std::vector<std::vector<uint8_t>> solutions;
    txnouttype script_type = Solver(txout.scriptPubKey, solutions, scriptFlags);
    CScript next_script = txout.scriptPubKey;

    // Memcoin: P2SH disabled - TX_SCRIPTHASH block removed
    if (script_type == TX_MULTISIG && !stack.script.empty()) {
        // Build a map of pubkey -> signature by matching sigs to pubkeys:
        assert(solutions.size() > 1);
        unsigned int num_pubkeys = solutions.size() - 2;
        unsigned int last_success_key = 0;
        for (const valtype &sig : stack.script) {
            for (unsigned int i = last_success_key; i < num_pubkeys; ++i) {
                const valtype &pubkey = solutions[i + 1];
                // We either have a signature for this pubkey, or we have found
                // a signature and it is valid
                if (data.signatures.count(CPubKey(pubkey).GetID()) ||
                    extractor_checker.CheckSig(sig, pubkey, next_script, scriptFlags, nullptr)) {
                    last_success_key = i + 1;
                    break;
                }
            }
        }
    }

    return data;
}

void UpdateInput(CTxIn &input, const SignatureData &data) {
    input.scriptSig = data.scriptSig;
}

void SignatureData::MergeSignatureData(SignatureData sigdata) {
    if (complete) {
        return;
    }
    if (sigdata.complete) {
        *this = std::move(sigdata);
        return;
    }
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    signatures.insert(std::make_move_iterator(sigdata.signatures.begin()),
                      std::make_move_iterator(sigdata.signatures.end()));
}

bool SignSignature(const SigningProvider &provider, const CScript &fromPubKey,
                   CMutableTransaction &txTo, unsigned int nIn,
                   const CTxOut &prevOut, SigHashType sigHashType, const uint32_t scriptFlags,
                   ScriptExecutionContextOpt const& context) {
    assert(nIn < txTo.vin.size());

    ScriptExecutionContextOpt tmp;
    const ScriptExecutionContext *pcontext;
    if (context) {
        pcontext = &*context;
    } else {
        // create a "limited" context (won't be able to sign SIGHASH_UTXOS or sign raw introspection scripts)
        tmp.emplace(nIn, prevOut, txTo);
        pcontext = &*tmp;
    }

    TransactionSignatureCreator creator(*pcontext, sigHashType);

    SignatureData sigdata;
    bool ret = ProduceSignature(provider, creator, fromPubKey, sigdata, scriptFlags);
    UpdateInput(txTo.vin.at(nIn), sigdata);
    return ret;
}

bool SignSignature(const SigningProvider &provider, const CTransaction &txFrom,
                   CMutableTransaction &txTo, unsigned int nIn,
                   SigHashType sigHashType, const uint32_t scriptFlags, ScriptExecutionContextOpt const& context) {
    assert(nIn < txTo.vin.size());
    CTxIn &txin = txTo.vin[nIn];
    assert(txin.prevout.GetN() < txFrom.vout.size());
    const CTxOut &txout = txFrom.vout[txin.prevout.GetN()];

    return SignSignature(provider, txout.scriptPubKey, txTo, nIn, txout, sigHashType, scriptFlags, context);
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker final : public BaseSignatureChecker {
public:
    DummySignatureChecker() {}
    bool CheckSig(const ByteView &scriptSig,
                  const std::vector<uint8_t> &vchPubKey,
                  const ByteView &scriptCode, uint32_t scriptFlags, size_t *pBytesHashed) const override {
        if (pBytesHashed) *pBytesHashed = 0;
        return true;
    }
};
const DummySignatureChecker DUMMY_CHECKER;

class DummySignatureCreator final : public BaseSignatureCreator {
private:
    char m_r_len = 32;
    char m_s_len = 32;

public:
    DummySignatureCreator(char r_len, char s_len)
        : m_r_len(r_len), m_s_len(s_len) {}
    const BaseSignatureChecker &Checker() const override {
        return DUMMY_CHECKER;
    }
    bool CreateSig(const SigningProvider &provider, std::vector<uint8_t> &vchSig, const CKeyID &keyid,
                   const CScript &scriptCode, uint32_t flags) const override {
        // Create a dummy signature that is a valid DER-encoding
        vchSig.assign(m_r_len + m_s_len + 7, '\000');
        vchSig[0] = 0x30;
        vchSig[1] = m_r_len + m_s_len + 4;
        vchSig[2] = 0x02;
        vchSig[3] = m_r_len;
        vchSig[4] = 0x01;
        vchSig[4 + m_r_len] = 0x02;
        vchSig[5 + m_r_len] = m_s_len;
        vchSig[6 + m_r_len] = 0x01;
        vchSig[6 + m_r_len + m_s_len] = SIGHASH_ALL | SIGHASH_FORKID;
        return true;
    }
};

template <typename M, typename K, typename V>
bool LookupHelper(const M &map, const K &key, V &value) {
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return true;
    }
    return false;
}

} // namespace

const BaseSignatureCreator &DUMMY_SIGNATURE_CREATOR = DummySignatureCreator(32, 32);
const BaseSignatureCreator &DUMMY_MAXIMUM_SIGNATURE_CREATOR = DummySignatureCreator(33, 32);
const SigningProvider &DUMMY_SIGNING_PROVIDER = SigningProvider();

bool HidingSigningProvider::GetPubKey(const CKeyID &keyid,
                                      CPubKey &pubkey) const {
    return m_provider->GetPubKey(keyid, pubkey);
}

bool HidingSigningProvider::GetKey(const CKeyID &keyid, CKey &key) const {
    if (m_hide_secret) {
        return false;
    }
    return m_provider->GetKey(keyid, key);
}

bool HidingSigningProvider::GetKeyOrigin(const CKeyID &keyid,
                                         KeyOriginInfo &info) const {
    if (m_hide_origin) {
        return false;
    }
    return m_provider->GetKeyOrigin(keyid, info);
}

bool FlatSigningProvider::GetPubKey(const CKeyID &keyid, CPubKey &pubkey) const {
    return LookupHelper(pubkeys, keyid, pubkey);
}
bool FlatSigningProvider::GetKeyOrigin(const CKeyID &keyid, KeyOriginInfo &info) const {
    return LookupHelper(origins, keyid, info);
}
bool FlatSigningProvider::GetKey(const CKeyID &keyid, CKey &key) const {
    return LookupHelper(keys, keyid, key);
}

FlatSigningProvider Merge(const FlatSigningProvider &a, const FlatSigningProvider &b) {
    FlatSigningProvider ret;
    ret.pubkeys = a.pubkeys;
    ret.pubkeys.insert(b.pubkeys.begin(), b.pubkeys.end());
    ret.keys = a.keys;
    ret.keys.insert(b.keys.begin(), b.keys.end());
    return ret;
}

bool IsSolvable(const SigningProvider &provider, const CScript &script, const uint32_t scriptFlags) {
    // This check is to make sure that the script we created can actually be
    // solved for and signed by us if we were to have the private keys. This is
    // just to make sure that the script is valid and that, if found in a
    // transaction, we would still accept and relay that transaction.
    SignatureData sigs;
    if (ProduceSignature(provider, DUMMY_SIGNATURE_CREATOR, script, sigs, scriptFlags)) {
        // VerifyScript check is just defensive, and should never fail.
        bool verified = VerifyScript(sigs.scriptSig, script, scriptFlags, DUMMY_CHECKER);
        assert(verified);
        return true;
    }
    return false;
}
