// Copyright (c) 2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <sync.h>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>


class PeerRateLimitRule {
public:
    PeerRateLimitRule(const std::string &rule);

    bool IsValid() const { return m_error.empty() && !m_name.empty(); }
    std::string GetName() const { return m_name; }
    uint64_t GetLimitMB() const { return m_limitMB; }
    uint32_t GetWindowMinutes() const { return m_windowMinutes; }
    uint32_t GetBanMinutes() const { return m_banMinutes; }
    std::string GetError() const { return m_error; }
    std::string GetDescription() const;
    std::string GetBanMessage() const;

private:
    std::string m_name;
    uint64_t m_limitMB{};
    uint32_t m_windowMinutes{};
    uint32_t m_banMinutes{};
    std::string m_error;
};


class SlidingWindowCounter {
public:
    SlidingWindowCounter(uint32_t numberOfBuckets, uint32_t bucketSeconds)
        : m_buckets(numberOfBuckets, 0), m_bucketSeconds(bucketSeconds) {}
    SlidingWindowCounter() : SlidingWindowCounter(1, 1) {}

    // Add to the counter and return the current value
    uint64_t Add(uint64_t bytes, int64_t nowSeconds);

private:
    void AdvanceTo(int64_t nowSeconds);

    std::vector<uint64_t> m_buckets;
    uint32_t m_bucketSeconds{};
    uint32_t m_head{};
    uint64_t m_windowSum{};
    int64_t m_lastUpdate{};
};


class ClientUsageTracker {
public:
    // Precondition: All rules must be IsValid() otherwise the app terminates with an assertion failure.
    explicit ClientUsageTracker(const std::vector<PeerRateLimitRule> &rules);

    // Records an amount of data that has been sent or received. If a peer rate limit rule was violated, the violated
    // rule is returned.
    std::optional<PeerRateLimitRule> RecordTransfer(uint64_t bytes, uint64_t now);

private:
    // Depending on the size of the time window in question, record usage in different size buckets to both optimize
    // precision and minimize consumed space
    // <= 6h:  1-minute buckets
    // <= 1d:  3-minute buckets
    // <= 1w: 15-minute buckets
    // <= 12w: 1-hour   buckets
    // <= 84w: 1-day    buckets
    // >  84w: 1-week   buckets
    // Returns a pair: {Number of buckets per window, Seconds per bucket}
    static std::pair<uint32_t, uint32_t> ChooseBucketScheme(const PeerRateLimitRule &r);

    Mutex m_mutex;
    std::vector<std::pair<PeerRateLimitRule, SlidingWindowCounter>> m_counters GUARDED_BY(m_mutex);
};
