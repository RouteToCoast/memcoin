// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2020-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <attributes.h>
#include <script/sighashtype.h>
#include <univalue.h>

#include <string>
#include <vector>

struct Amount;
class CBlock;
class CBlockHeader;
class CMutableTransaction;
class Config;
class CScript;
class CTransaction;
class CTxUndo;
struct PartiallySignedTransaction;
class uint160;
class uint256;
namespace token { class OutputData; struct SafeAmount; }

/** Verbosity level for JSONification of blocks */
enum class BlockTxVerbosity {
    SHOW_TXID,                                      //!< Only TXID for each transaction
    SHOW_DETAILS,                                   //!< Include TXID, inputs, outputs, and other common transaction information
    SHOW_DETAILS_AND_PREVOUT                        //!< The same as previous option with information about prevouts if available
};

/**
 * Fine-grained options for serialization of transaction and/or block data.
 * New fields may be added in the future.
 */
struct TransactionFormatOptions {
    bool include_hex = false;                       //!< Whether whole transaction "hex" entry will be included
    bool include_fee = false;                       //!< Whether transaction "fee" entry will be included
    bool include_patterns = false;                  //!< Whether "bytecodePattern" entries will be generated for scripts

    struct PrevoutOptions {
        bool nest_prevouts = false;                 //!< Whether prevout fields will be nested under their own "prevout" object
        bool include_height = false;                //!< Whether prevout "height" entry will be included
        bool include_generated = false;             //!< Whether prevout "generated" entry will be included
        PrevoutOptions() noexcept = default;
    };

    std::optional<PrevoutOptions> prevout_options;  //!< Whether prevout fields will be included

    /** Block-level options, used by blockToJSON() only */
    struct BlockLevel {
        /// Whether to show only txids and not tx contents. If true, above fields are ignored completely by blockToJSON.
        bool txids_only = false;
    } block_level;

    TransactionFormatOptions& WithHex(bool enable = true) { include_hex = enable; return *this; }
    TransactionFormatOptions& WithPatterns(bool enable = true) { include_patterns = enable; return *this; }

    TransactionFormatOptions() noexcept = default;
    // Implicit conversion from BlockTxVerbosity
    TransactionFormatOptions(BlockTxVerbosity) noexcept;
};

// core_read.cpp
CScript ParseScript(const std::string &s);
std::string ScriptToAsmStr(const CScript &script, bool fAttemptSighashDecode = false);
[[nodiscard]] bool DecodeHexTx(CMutableTransaction &tx,
                               const std::string &strHexTx);
[[nodiscard]] bool DecodeHexBlk(CBlock &, const std::string &strHexBlk);
bool DecodeHexBlockHeader(CBlockHeader &, const std::string &hex_header);

/**
 * Parse a hex string into 256 bits
 * @param[in] strHex a hex-formatted, 64-character string
 * @param[out] result the result of the parsing
 * @returns true if successful, false if not
 *
 * @see ParseHashV for an RPC-oriented version of this
 */
bool ParseHashStr(const std::string &strHex, uint256 &result);
/**
 * Variant of above: Parse a hex string into 160 bits.
 * @param[in] strHex a hex-formatted, 40-character string
 * @param[out] result the result of the parsing
 * @returns true if successful, false if not
 */
bool ParseHashStr(const std::string &strHex, uint160 &result);
std::vector<uint8_t> ParseHexUV(const UniValue &v, const std::string &strName);
[[nodiscard]] bool DecodePSBT(PartiallySignedTransaction &psbt,
                              const std::string &base64_tx, std::string &error);
SigHashType ParseSighashString(const UniValue &sighash);

/// Decode a UniValue object whose keys are "category", "amount" (optional), "nft" (optional),
/// Within "nft" which is a JSON object there is: "capability" (optional), "commitment" (optional)
/// @throws std::runtime_error if not an object or if the "category" key is missing, or if a field is invalid.
[[nodiscard]] token::OutputData DecodeTokenDataUV(const UniValue &obj);

/// @pre UniValue `obj` must be a JSON numeric or a JSON string which contains an integral number. Values must be in
///      the non-negative int64_t range.
/// @returns A valid amount, after parsing the string or simple conversion from JSON numeric
/// @throws std::runtime_error if the preconditions are not satisfied.
[[nodiscard]] token::SafeAmount DecodeSafeAmount(const UniValue &obj);

// core_write.cpp
UniValue ValueFromAmount(const Amount &amount);
std::string FormatScript(const CScript &script);
std::string EncodeHexTx(const CTransaction &tx);
std::string SighashToStr(uint8_t sighash_type);
UniValue::Object ScriptPubKeyToUniv(const Config &config, const CScript &scriptPubKey, bool fIncludeHex,
                                    bool fIncludeP2SH = false, bool include_pattern = false);
UniValue::Object ScriptToUniv(const Config &config, const CScript &script, bool include_address,
                              bool include_type = true, bool include_pattern = false);
UniValue::Object TransactionToUniv(const Config &config, const CTransaction &tx, const CTxUndo *txundo = nullptr,
                                   const TransactionFormatOptions &options = {}, size_t extraFieldsToReserve = 0u);
UniValue::Object TokenDataToUniv(const token::OutputData &token);

/// Returns a UniValue::VSTR (string) for any token amount.  We are forced to unconditionally wrap token amounts
/// as strings since they may exceed 9007199254740991, which is the largest safe JSON numeric value (~53 bits).
[[nodiscard]] UniValue SafeAmountToUniv(token::SafeAmount val);

/// @param[in] script - the script to parse into a bytecode pattern JSON object.
/// @param[out] pOptLastPush - `nullptr` ok; optional vector to store the last push of `script` (if any). If there was
///                            an error or if there are no pushes, then `*pOptLastPush` will be `std::nullopt`.
/// @returns An object that describes the "bytecode pattern" information for any script.
[[nodiscard]] UniValue::Object ScriptToByteCodePatternUniv(const CScript &script,
                                                           std::optional<std::vector<uint8_t>> *pOptLastPush = nullptr);
