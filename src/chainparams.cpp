// Copyright (c) 2010 Bit Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2023 The Bitcoin developers
// Copyright (c) 2026 Memcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsconstants.h>
#include <chainparamsseeds.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <netbase.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <cassert>
#include <cstring>
#include <memory>
#include <stdexcept>

static CBlock CreateGenesisBlock(const char *pszTimestamp,
                                 const CScript &genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << ScriptInt::fromIntUnchecked(486604799)
                  << CScriptNum::fromIntUnchecked(4)
                  << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                          (const uint8_t *)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block.
 * The coinbase timestamp message establishes Memcoin's origin.
 */
CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits,
                          int32_t nVersion, const Amount genesisReward) {
    const char *pszTimestamp =
        "It's nice how anyone with just a CPU can compete fairly equally right now";

    const CScript genesisOutputScript =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
}

// ============================================================
//  MAIN NETWORK
// ============================================================
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;

        consensus.nSubsidyHalvingInterval = 157500;

        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash   = BlockHash();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight   = 0;

        consensus.powLimit = uint256S(
            "0200000000000000000000000000000000000000000000000000000000000000");

        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // 2 weeks
        consensus.nPowTargetSpacing  = 10 * 60;           // 10 minutes

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting            = false;

        consensus.nASERTHalfLife = 2 * 60 * 60; // 2 hours - optimized for new chain

        consensus.nMinimumChainWork  = uint256S("0x00");
        consensus.defaultAssumeValid = BlockHash();

        consensus.uahfHeight             = 0;
        consensus.daaHeight              = 0;
        consensus.magneticAnomalyHeight  = 0x7FFFFFFF;
        consensus.gravitonHeight         = 0;
        consensus.phononHeight           = 0;
        consensus.axionActivationTime    = 0x7FFFFFFF;
        consensus.upgrade8Height         = 0;
        consensus.upgrade9Height         = 0x7FFFFFFF;
        consensus.upgrade10Height        = 0;
        consensus.upgrade11Height        = 0x7FFFFFFF;
        consensus.upgrade12ActivationTime    = 0x7FFFFFFF;
        consensus.upgrade2027ActivationTime  = 0x7FFFFFFF;

        consensus.nDefaultConsensusBlockSize = DEFAULT_CONSENSUS_BLOCK_SIZE;
        consensus.nDefaultGeneratedBlockSizePercent = 50.0;

        assert(consensus.nDefaultGeneratedBlockSizePercent >= 0.0
               && consensus.nDefaultGeneratedBlockSizePercent <= 100.0);
        assert(consensus.GetDefaultGeneratedBlockSizeBytes()
               <= consensus.nDefaultConsensusBlockSize);

        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
            0,
            0x1f0ffff0,
            1773000000,
        };

        consensus.ablaConfig = abla::Config::MakeDefault(
            consensus.nDefaultConsensusBlockSize, /* fixedSize = */ false);
        // Memcoin: cap ABLA maximum at 64 MB (32 MB per component)
        consensus.ablaConfig.epsilonMax = 32u * 1024u * 1024u;
        consensus.ablaConfig.betaMax    = 32u * 1024u * 1024u;
        assert(abla::State(consensus.ablaConfig, 0).GetBlockSizeLimit()
               == consensus.nDefaultConsensusBlockSize);
        assert(!consensus.ablaConfig.IsFixedSize());

        diskMagic[0] = 0x4D; // 'M'
        diskMagic[1] = 0x45; // 'E'
        diskMagic[2] = 0x4D; // 'M'
        diskMagic[3] = 0x43; // 'C'
        netMagic[0]  = 0x4D;
        netMagic[1]  = 0x45;
        netMagic[2]  = 0x4D;
        netMagic[3]  = 0x43;

        nDefaultPort      = 9333;
        nPruneAfterHeight = 100000;

        m_assumed_blockchain_size   = 0;
        m_assumed_chain_state_size  = 0;

        genesis = CreateGenesisBlock(
            1773000000,  // nTime
            4268,        // nNonce
            0x1f0ffff0,  // nBits
            1,           // nVersion
            50 * COIN    // genesis reward
        );
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0x2c38642d80d9e38179f22445a0480c7e6ce8d2ae28096088c03ef69c5ff100df"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x830db26f5886643896ce164a729994c619178b7f56fbbc5c03f131a2f2e46b97"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // vSeeds.emplace_back("seed.memcoin.example");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 50);  // 'M'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 5);
        base58Prefixes[SECRET_KEY]     = std::vector<uint8_t>(1, 178);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        cashaddrPrefix = "mem";

        fDefaultConsistencyChecks = false;
        fRequireStandard          = true;
        m_is_test_chain           = false;

        checkpointData = {/* .mapCheckpoints = */
            {
                {100,  BlockHash(uint256S("0x91478d4c5a2429887fe538eb4a569ad0e0944161393fa143f623e8a69d8e866e"))},
                {200,  BlockHash(uint256S("0x050a59af2a53ea466652f4a34c9189c3ea38593266834f44f5bdc13b35e72ad6"))},
                {500,  BlockHash(uint256S("0xe4ff72ab1a092ff7c1ab264603af14b05bc30c7608fe8a90c848bb0c5bbdca97"))},
                {1000, BlockHash(uint256S("0x4971e8e533ced98bd7dff56bcd5e3010f4c32f6350659131a83860b312f67953"))},
                {1500, BlockHash(uint256S("0x5b55778f9c5cc923b2760632fee17e6fc2c98d9d45ec95e5b2ae62428c382d1a"))},
            }};
        chainTxData    = ChainTxData{0, 0, 0};
    }
};

// ============================================================
//  TESTNET
// ============================================================
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;

        consensus.nSubsidyHalvingInterval = 157500;

        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash   = BlockHash();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight   = 0;

        consensus.powLimit = uint256S(
            "0200000000000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan           = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing            = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting            = false;

        consensus.nASERTHalfLife = 60 * 60; // 1 hour on testnet

        consensus.nMinimumChainWork  = uint256S("0x00");
        consensus.defaultAssumeValid = BlockHash();

        consensus.uahfHeight             = 0;
        consensus.daaHeight              = 0;
        consensus.magneticAnomalyHeight  = 0x7FFFFFFF;
        consensus.gravitonHeight         = 0;
        consensus.phononHeight           = 0;
        consensus.axionActivationTime    = 0x7FFFFFFF;
        consensus.upgrade8Height         = 0;
        consensus.upgrade9Height         = 0x7FFFFFFF;
        consensus.upgrade10Height        = 0;
        consensus.upgrade11Height        = 0x7FFFFFFF;
        consensus.upgrade12ActivationTime   = 0x7FFFFFFF;
        consensus.upgrade2027ActivationTime = 0x7FFFFFFF;

        consensus.nDefaultConsensusBlockSize = DEFAULT_CONSENSUS_BLOCK_SIZE;
        consensus.nDefaultGeneratedBlockSizePercent = 50.0;

        assert(consensus.nDefaultGeneratedBlockSizePercent >= 0.0
               && consensus.nDefaultGeneratedBlockSizePercent <= 100.0);
        assert(consensus.GetDefaultGeneratedBlockSizeBytes()
               <= consensus.nDefaultConsensusBlockSize);

        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
            0,
            0x1f0ffff0,
            1773000000,
        };

        consensus.ablaConfig = abla::Config::MakeDefault(
            consensus.nDefaultConsensusBlockSize, /* fixedSize = */ true);
        assert(abla::State(consensus.ablaConfig, 0).GetBlockSizeLimit()
               == consensus.nDefaultConsensusBlockSize);
        assert(consensus.ablaConfig.IsFixedSize());

        diskMagic[0] = 0x4D; // 'M'
        diskMagic[1] = 0x45; // 'E'
        diskMagic[2] = 0x4D; // 'M'
        diskMagic[3] = 0x54; // 'T'
        netMagic[0]  = 0x4D;
        netMagic[1]  = 0x45;
        netMagic[2]  = 0x4D;
        netMagic[3]  = 0x54;

        nDefaultPort      = 19333;
        nPruneAfterHeight = 1000;

        m_assumed_blockchain_size  = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1714000000, 0, 0x1f0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // TODO: assert after mining testnet genesis block

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 50);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY]     = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "memtest";

        fDefaultConsistencyChecks = false;
        fRequireStandard          = false;
        m_is_test_chain           = true;

        checkpointData = {/* .mapCheckpoints = */ {}};
        chainTxData    = ChainTxData{0, 0, 0};
    }
};

// ============================================================
//  REGTEST
// ============================================================
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = CBaseChainParams::REGTEST;

        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height  = 0;
        consensus.BIP34Height  = 100000000;
        consensus.BIP34Hash    = BlockHash();
        consensus.BIP65Height  = 1351;
        consensus.BIP66Height  = 1251;
        consensus.CSVHeight    = 576;

        consensus.powLimit = uint256S(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan           = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing            = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting            = true;

        consensus.nASERTHalfLife = 2 * 60 * 60; // 2 hours

        consensus.nMinimumChainWork  = uint256S("0x00");
        consensus.defaultAssumeValid = BlockHash();

        consensus.uahfHeight             = 0;
        consensus.daaHeight              = 0;
        consensus.magneticAnomalyHeight  = 0x7FFFFFFF;
        consensus.gravitonHeight         = 0;
        consensus.phononHeight           = 0;
        consensus.axionActivationTime    = 0x7FFFFFFF;
        consensus.upgrade8Height         = 0;
        consensus.upgrade9Height         = 0x7FFFFFFF;
        consensus.upgrade10Height        = 0;
        consensus.upgrade11Height        = 0x7FFFFFFF;
        consensus.upgrade12ActivationTime   = 0x7FFFFFFF;
        consensus.upgrade2027ActivationTime = 0x7FFFFFFF;

        consensus.nDefaultConsensusBlockSize = DEFAULT_CONSENSUS_BLOCK_SIZE;
        consensus.nDefaultGeneratedBlockSizePercent = 50.0;

        assert(consensus.nDefaultGeneratedBlockSizePercent >= 0.0
               && consensus.nDefaultGeneratedBlockSizePercent <= 100.0);
        assert(consensus.GetDefaultGeneratedBlockSizeBytes()
               <= consensus.nDefaultConsensusBlockSize);

        consensus.ablaConfig = abla::Config::MakeDefault(
            consensus.nDefaultConsensusBlockSize, /* fixedSize = */ false);
        // Memcoin: cap ABLA maximum at 64 MB (32 MB per component)
        consensus.ablaConfig.epsilonMax = 32u * 1024u * 1024u;
        consensus.ablaConfig.betaMax    = 32u * 1024u * 1024u;
        assert(abla::State(consensus.ablaConfig, 0).GetBlockSizeLimit()
               == consensus.nDefaultConsensusBlockSize);
        assert(!consensus.ablaConfig.IsFixedSize());

        diskMagic[0] = 0xfa;
        diskMagic[1] = 0xbf;
        diskMagic[2] = 0xb5;
        diskMagic[3] = 0xda;
        netMagic[0]  = 0xda;
        netMagic[1]  = 0xb5;
        netMagic[2]  = 0xbf;
        netMagic[3]  = 0xfa;

        nDefaultPort      = 18444;
        nPruneAfterHeight = 1000;

        m_assumed_blockchain_size  = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1296688602, 0, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();


        vFixedSeeds.clear();
        vSeeds.clear();

        fDefaultConsistencyChecks = true;
        fRequireStandard          = true;
        m_is_test_chain           = true;

        checkpointData = {/* .mapCheckpoints = */ {}};

        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 50);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY]     = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchreg";
    }
};

// ============================================================
//  Stubs
// ============================================================
class CTestNet4Params : public CTestNetParams {};
class CScaleNetParams : public CTestNetParams {};
class CChipNetParams  : public CTestNetParams {};

// ============================================================
//  Global chain selection
// ============================================================
static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN)     return std::make_unique<CMainParams>();
    if (chain == CBaseChainParams::TESTNET)  return std::make_unique<CTestNetParams>();
    if (chain == CBaseChainParams::TESTNET4) return std::make_unique<CTestNet4Params>();
    if (chain == CBaseChainParams::REGTEST)  return std::make_unique<CRegTestParams>();
    if (chain == CBaseChainParams::SCALENET) return std::make_unique<CScaleNetParams>();
    if (chain == CBaseChainParams::CHIPNET)  return std::make_unique<CChipNetParams>();

    throw std::runtime_error(
        strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

SeedSpec6::SeedSpec6(const char *pszHostPort)
{
    const CService service = LookupNumeric(pszHostPort, 0);
    if (!service.IsValid() || service.GetPort() == 0)
        throw std::invalid_argument(
            strprintf("Unable to parse numeric-IP:port pair: %s", pszHostPort));
    if (!service.IsRoutable())
        throw std::invalid_argument(strprintf("Not routable: %s", pszHostPort));
    *this = SeedSpec6(service);
}