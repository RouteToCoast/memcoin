// Copyright (c) 2009-2010 Bit Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <keystore.h>

#include <key.h>
#include <pubkey.h>
#include <util/system.h>

void CBasicKeyStore::ImplicitlyLearnRelatedKeyScripts(const CPubKey &pubkey) {
    AssertLockHeld(cs_KeyStore);
    CKeyID key_id = pubkey.GetID();
    // We must actually know about this key already.
    assert(HaveKey(key_id) || mapWatchKeys.count(key_id));
    // This adds the redeemscripts necessary to detect alternative outputs using
    // the same keys. Also note that having superfluous scripts in the keystore
    // never hurts. They're only used to guide recursion in signing and IsMine
    // logic - if a script is present but we can't do anything with it, it has
    // no effect. "Implicitly" refers to fact that scripts are derived
    // automatically from existing keys, and are present in memory, even without
    // being explicitly loaded (e.g. from a file).

    // Right now there are none so do nothing.
}

bool CBasicKeyStore::GetPubKey(const CKeyID &address,
                               CPubKey &vchPubKeyOut) const {
    CKey key;
    if (!GetKey(address, key)) {
        LOCK(cs_KeyStore);
        WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
        if (it != mapWatchKeys.end()) {
            vchPubKeyOut = it->second;
            return true;
        }
        return false;
    }
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CBasicKeyStore::AddKeyPubKey(const CKey &key, const CPubKey &pubkey) {
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    ImplicitlyLearnRelatedKeyScripts(pubkey);
    return true;
}

bool CBasicKeyStore::HaveKey(const CKeyID &address) const {
    LOCK(cs_KeyStore);
    return mapKeys.count(address) > 0;
}

std::set<CKeyID> CBasicKeyStore::GetKeys() const {
    LOCK(cs_KeyStore);
    std::set<CKeyID> set_address;
    for (const auto &mi : mapKeys) {
        set_address.insert(mi.first);
    }
    return set_address;
}

bool CBasicKeyStore::GetKey(const CKeyID &address, CKey &keyOut) const {
    LOCK(cs_KeyStore);
    KeyMap::const_iterator mi = mapKeys.find(address);
    if (mi != mapKeys.end()) {
        keyOut = mi->second;
        return true;
    }
    return false;
}

static bool ExtractPubKey(const CScript &dest, CPubKey &pubKeyOut) {
    // TODO: Use Solver to extract this?
    CScript::const_iterator pc = dest.begin();
    opcodetype opcode;
    std::vector<uint8_t> vch;
    if (!dest.GetOp(pc, opcode, vch) || !CPubKey::ValidSize(vch)) {
        return false;
    }
    pubKeyOut = CPubKey(vch);
    if (!pubKeyOut.IsFullyValid()) {
        return false;
    }
    if (!dest.GetOp(pc, opcode, vch) || opcode != OP_CHECKSIG ||
        dest.GetOp(pc, opcode, vch)) {
        return false;
    }
    return true;
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest) {
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) {
        mapWatchKeys[pubKey.GetID()] = pubKey;
        ImplicitlyLearnRelatedKeyScripts(pubKey);
    }
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest) {
    LOCK(cs_KeyStore);
    setWatchOnly.erase(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) {
        mapWatchKeys.erase(pubKey.GetID());
    }
    // Related CScripts are not removed; having superfluous scripts around is
    // harmless (see comment in ImplicitlyLearnRelatedKeyScripts).
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const {
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const {
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

CKeyID GetKeyForDestination(const CKeyStore &store [[maybe_unused]], const CTxDestination &dest) {
    // Only supports destinations which map to single public keys, i.e. P2PKH.
    if (auto *id = std::get_if<CKeyID>(&dest)) {
        return *id;
    }
    return CKeyID();
}

bool HaveKey(const CKeyStore &store, const CKey &key) {
    CKey key2;
    key2.Set(key.begin(), key.end(), !key.IsCompressed());
    return store.HaveKey(key.GetPubKey().GetID()) ||
           store.HaveKey(key2.GetPubKey().GetID());
}
