# Memcoin (MEM)

A minimal proof-of-work cryptocurrency.

Memory-hard proof-of-work. Zero-fee instant payments. No development fund. No governance.

---

## Overview

**PoW:** Yesmem — memory-hard algorithm requiring ~7 GB RAM per thread.
Eliminates GPU and ASIC mining. Any standard PC can participate.

**Payments:** Zero-fee instant payment system (TX1/TX2).
Funds are locked on-chain at broadcast. No confirmation required for everyday use.

**Supply:** Fixed emission schedule converging to equilibrium ~24,500,000 MEM.
Permanent 7 MEM floor reward offsets key loss attrition.

---

## Parameters

| Parameter         | Value                        |
|-------------------|------------------------------|
| Ticker            | MEM                          |
| Block time        | 600 seconds                  |
| Max block size    | 32 MB (256 MB hard cap)      |
| PoW               | Yesmem (N=1,835,008, r=32)   |
| Memory/thread     | ~7 GB                        |
| P2P port          | 9333                         |
| RPC port          | 9332                         |
| Address prefix    | M                            |
| Network magic     | 0x4D454D43 (MEMC)            |

---

## Building

See [INSTALL.md](INSTALL.md) for build instructions.

---

## License

Distributed under the MIT software license.
See [COPYING](COPYING) for details.
