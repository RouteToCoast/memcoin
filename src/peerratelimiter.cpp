// Copyright (c) 2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <peerratelimiter.h>

#include <logging.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>

#include <algorithm>
#include <array>
#include <cassert>

namespace {

inline constexpr uint64_t MB_IN_GB{1000ULL};
inline constexpr uint64_t MB_IN_TB{1000ULL * 1000ULL};
inline constexpr uint64_t MB_IN_PB{1000ULL * 1000ULL * 1000ULL};
inline constexpr uint32_t MINS_IN_H{60};
inline constexpr uint32_t MINS_IN_D{60 * 24};
inline constexpr uint32_t MINS_IN_W{60 * 24 * 7};

// Allowed data units: MB, GB, TB, PB
uint64_t ParseDataString(const std::string &s) {
    std::string lower = TrimString(ToLower(s));
    std::string_view sv(lower);

    if (sv.empty() || !isdigit(sv[0])) {
        throw std::runtime_error(strprintf("Invalid data amount string '%s': Must start with a number.", s));
    }

    size_t unitPos = sv.find_first_not_of("0123456789.");
    if (unitPos == std::string_view::npos) {
        // No unit given -> assume MB
        return std::stoull(std::string(sv));
    }

    uint64_t value = std::stoull(std::string(sv.substr(0, unitPos)));
    std::string_view unit = sv.substr(unitPos);

    if (unit == "mb") return value;
    if (unit == "gb") return value * MB_IN_GB;
    if (unit == "tb") return value * MB_IN_TB;
    if (unit == "pb") return value * MB_IN_PB;

    throw std::runtime_error(strprintf("Invalid data unit: %s", unit));
}

// Allowed time units: m, h, d, w
uint32_t ParseTimeString(const std::string &s) {
    std::string lower = TrimString(ToLower(s));
    std::string_view sv(lower);

    if (sv.empty() || !isdigit(sv[0])) {
        throw std::runtime_error(strprintf("Invalid time duration string '%s': Must start with a number.", s));
    }

    size_t unitPos = sv.find_first_not_of("0123456789");
    if (unitPos == std::string_view::npos) {
        // No unit given, assume minutes
        return std::stoi(std::string(sv));
    }

    int value = std::stoi(std::string(sv.substr(0, unitPos)));
    if (value < 0) {
        throw std::runtime_error(strprintf("Invalid time unit value: %d", value));
    }
    std::string_view unit = sv.substr(unitPos);

    if (unit == "m") return value;
    if (unit == "h") return value * MINS_IN_H;
    if (unit == "d") return value * MINS_IN_D;
    if (unit == "w") return value * MINS_IN_W;

    throw std::runtime_error(strprintf("Invalid time unit: %s", unit));
}

std::string ToDataStr(uint64_t mb) {
    constexpr std::array<std::pair<const char *, uint64_t>, 4> dataUnits{{
        {"PB", MB_IN_PB},
        {"TB", MB_IN_TB},
        {"GB", MB_IN_GB},
        {"MB", 1},
    }};
    static_assert(std::all_of(dataUnits.begin(), dataUnits.end(), [](const auto &pair){ return pair.second > 0; }),
                  "Prevent division by zero");

    for (const auto& [dataUnitName, dataUnitMBs] : dataUnits) {
        if (mb % dataUnitMBs == 0) {
            uint32_t numUnits = mb / dataUnitMBs;
            return std::to_string(numUnits) + " " + dataUnitName;
        }
    }
    assert(false); // Should never happen, indicates unreachable code. Use std::unreachable() when we switch to C++23.
    return {};
}

std::string ToTimeStr(uint32_t minutes) {
    constexpr std::array<std::pair<const char *, uint32_t>, 4> periods{{
        {"week",   MINS_IN_W},
        {"day",    MINS_IN_D},
        {"hour",   MINS_IN_H},
        {"minute", 1},
    }};
    static_assert(std::all_of(periods.begin(), periods.end(), [](const auto &pair){ return pair.second > 0; }),
                  "Prevent division by zero");

    for (const auto& [periodName, periodMinutes] : periods) {
        if (minutes % periodMinutes == 0) {
            uint32_t numPeriods = minutes / periodMinutes;
            return std::to_string(numPeriods) + " " + periodName + ((numPeriods > 1) ? "s" : "");
        }
    }
    assert(false); // Should never happen, indicates unreachable code. Use std::unreachable() when we switch to C++23.
    return {};
}

} // namespace

PeerRateLimitRule::PeerRateLimitRule(const std::string &rule) {
    std::string line = TrimString(rule);
    if (line.empty()) {
        m_error = "empty rule";
        return;
    }

    // Expected format: <data>/<window>:<ban>
    std::string_view sv(line);

    auto colon = sv.find(':');
    if (colon == std::string_view::npos) {
        m_error = "missing ':'";
        return;
    }

    std::string_view left = sv.substr(0, colon);

    auto slash = left.find('/');
    if (slash == std::string_view::npos) {
        m_error = "missing '/'";
        return;
    }

    std::string limitPart{left.substr(0, slash)};
    std::string windowPart{left.substr(slash + 1, colon)};
    std::string banPart{sv.substr(colon + 1)};

    try {
        m_name = rule;
        m_limitMB = ParseDataString(limitPart);
        m_windowMinutes = ParseTimeString(windowPart);
        m_banMinutes = ParseTimeString(banPart);
    } catch (const std::exception& e) {
        m_error = e.what();
        return;
    }

    if (m_limitMB <= 0) {
        m_error = "zero data limit";
    } else if (m_limitMB > MB_IN_PB * 10'000ULL) {
        m_error = "data limit greater than 10,000 PB";
    } else if (m_windowMinutes == 0) {
        m_error = "zero time window";
    } else if (m_windowMinutes > MINS_IN_W * 10'000) {
        m_error = "time window greater than 10,000 weeks";
    } else if (m_banMinutes > MINS_IN_W * 10'000) {
        m_error = "ban time greater than 10,000 weeks";
    }
}

std::string PeerRateLimitRule::GetDescription() const {
    return strprintf("%s transferred within %s -> ban for %s",
                     ToDataStr(m_limitMB), ToTimeStr(m_windowMinutes), ToTimeStr(m_banMinutes));
}

std::string PeerRateLimitRule::GetBanMessage() const {
    return strprintf("Banned for %s", ToTimeStr(m_banMinutes));
}

uint64_t SlidingWindowCounter::Add(uint64_t bytes, int64_t nowSeconds) {
    AdvanceTo(nowSeconds);
    assert(m_head < m_buckets.size());
    m_buckets[m_head] += bytes;
    m_windowSum += bytes;
    return m_windowSum;
}

void SlidingWindowCounter::AdvanceTo(int64_t nowSeconds) {
    if (m_lastUpdate == 0) {
        // First time this is called, initialize last update time.
        m_lastUpdate = nowSeconds;
    }

    if (nowSeconds <= m_lastUpdate) return; // Time has not advanced, so do nothing

    const auto elapsedSeconds = nowSeconds - m_lastUpdate;
    const uint32_t numberOfShifts = m_bucketSeconds ? elapsedSeconds / m_bucketSeconds : 0;

    if (numberOfShifts == 0) {
        // Not enough time has passed to advance to the next bucket
        return;
    }

    const size_t nBuckets = m_buckets.size();

    if (numberOfShifts >= nBuckets) {
        // A full window period (or more) has passed. All data is invalid.
        // This is a fast path that avoids iterating.
        std::fill(m_buckets.begin(), m_buckets.end(), 0);
        m_windowSum = 0;
    } else {
        for (uint32_t i = 0; i < numberOfShifts; ++i) {
            m_head = (m_head + 1u) % nBuckets;
            m_windowSum -= m_buckets[m_head];
            m_buckets[m_head] = 0;
        }
    }

    m_lastUpdate += numberOfShifts * m_bucketSeconds;
}

ClientUsageTracker::ClientUsageTracker(const std::vector<PeerRateLimitRule> &rules) {
    for (const auto& rule : rules) {
        assert(rule.IsValid());
        const auto& [numBuckets, bucketSeconds] = ChooseBucketScheme(rule);
        m_counters.emplace_back(std::piecewise_construct, std::forward_as_tuple(rule),
                                std::forward_as_tuple(numBuckets, bucketSeconds));
    }
    // Sort m_counters so that the rules with the most severe ban times are handled first
    std::sort(m_counters.begin(), m_counters.end(), [](auto const &lhs, auto const &rhs) {
        return lhs.first.GetBanMinutes() > rhs.first.GetBanMinutes();
    });
}

std::optional<PeerRateLimitRule> ClientUsageTracker::RecordTransfer(uint64_t bytes, uint64_t now) {
    LOCK(m_mutex);
    for (auto& [rule, counter] : m_counters) {
        uint64_t usage = counter.Add(bytes, now);
        if (usage >= rule.GetLimitMB() * 1000ULL * 1000ULL) {
            return rule;
        }
    }
    return std::nullopt;
}

std::pair<uint32_t, uint32_t> ClientUsageTracker::ChooseBucketScheme(const PeerRateLimitRule &r) {
    uint32_t bucketSeconds;
    if (r.GetWindowMinutes() <= 10) {
        // <= 10m: 1-second buckets
        bucketSeconds = 1;
    } else if (r.GetWindowMinutes() <= MINS_IN_H) {
        // <= 1h: 10-second buckets
        bucketSeconds = 10;
    } else if (r.GetWindowMinutes() <= 6 * MINS_IN_H) {
        // <= 6h: 1-minute buckets
        bucketSeconds = 60;
    } else if (r.GetWindowMinutes() <= MINS_IN_D) {
        // <= 1d: 3-minute buckets
        bucketSeconds = 60 * 3;
    } else if (r.GetWindowMinutes() <= MINS_IN_W) {
        // <= 1w: 15-minute buckets
        bucketSeconds = 60 * 15;
    } else if (r.GetWindowMinutes() <= 12 * MINS_IN_W) {
        // <= 12w: 1-hour buckets
        bucketSeconds = 60 * MINS_IN_H;
    } else if (r.GetWindowMinutes() <= 84 * MINS_IN_W) {
        // <= 84w: 1-day buckets
        bucketSeconds = 60 * MINS_IN_D;
    } else {
        // > 84w: 1-week buckets
        bucketSeconds = 60 * MINS_IN_W;
    }
    uint32_t numberOfBuckets = (r.GetWindowMinutes() * 60) / bucketSeconds;
    return {numberOfBuckets, bucketSeconds};
}
