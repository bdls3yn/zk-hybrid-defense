# zk-hybrid-defense

> **Doctoral Research Project** — Azerbaijan Technical University, 2022–2026  
> Specialty: 3339.01 — Information Security Systems  
> Author: Abdulhuseyn Agayev · ORCID: [0000-0003-4930-0672](https://orcid.org/0000-0003-4930-0672)

## Overview

**zk-hybrid-defense** is a two-layer hybrid cryptographic security framework for Ethereum smart contracts, combining:

1. **ZK-HHCF** — Zero-Knowledge + Homomorphic Encryption hybrid for privacy-preserving transaction verification
2. **ThreatDetector** — Adaptive real-time on-chain detection of DDoS, Sybil, and Replay attacks

Both systems are deployed on **Ethereum Sepolia testnet** and validated with real transaction data.

---

## Deployed Contracts (Ethereum Sepolia)

| Contract | Address | Deploy Gas |
|---|---|---|
| HybridGuardian | `0x5FC0Dbf8f4D1fE65A313354908f7ceE3110aCe78` | 1,328,713 |
| Groth16Verifier | `0x76DB84...` (generated) | ~980,000 |
| ThreatDetector v2 | `0x733a81BCBF22815675e788D3e406Dc2f0cE71E8f` | 1,387,453 |

---

## Section 3.1 — ZK-HHCF

Proves that a private transaction amount satisfies a range constraint without revealing the actual value, using Groth16 ZK proof + CKKS homomorphic encryption + keccak256 on-chain commitment.

### Key Results (N=1000 runs, Apple M2)

| Metric | Value |
|---|---|
| ZK proof generation — mean | 0.317 s |
| ZK proof generation — std | 0.049 s |
| ZK proof generation — P95 | 0.323 s |
| ZK proof generation — P99 | 0.335 s |
| CKKS encryption — mean | 3.50 ms |
| CKKS encryption — P95 | 3.72 ms |
| On-chain verification gas | 410,966 |
| On-chain data size | 32 bytes (keccak256 commitment) |
| Off-chain ciphertext | 334 KB (CKKS, never on-chain) |
| Data reduction factor | 10,450x |
| Memory peak (prover, Python) | 0.32 MB |
| Rejected transactions | 0 / all tests |
| vs. Zether | 4.1x cheaper (410K vs ~1.7M gas) |

### Gas Breakdown (submitProof = 410,966 gas)

| Component | Gas (approx.) | Share |
|---|---|---|
| Groth16 pairing checks (0x08) | 280,000 | 68.1% |
| ECADD/ECMUL helper calls | 20,000 | 4.9% |
| SSTORE (commitment mapping) | 20,000 | 4.9% |
| Calldata decoding & dispatch | 65,000 | 15.8% |
| Event emission (ProofVerified) | 25,966 | 6.3% |

### Workflow
amount=500, maxAmount=1000 → Circom LessEqThan32 circuit
Groth16 proof generated (0.317s mean) → proof.json
TenSEAL CKKS encrypt(amount) → 334 KB ciphertext (local only)
keccak256(ciphertext) → 32-byte commitment
HybridGuardian.submitProof(pA, pB, pC, pubSignals, cipherHash)
ProofVerified event emitted on Sepolia


Sepolia TX: `0x1d2f0786c3f6e60403fcd2d8402c7d5570e0e26c981d07d03092c0f62444074b`

---

## Section 3.2 — ThreatDetector

On-chain adaptive threat detection with cumulative reputation score (0–100):

| Attack | Detection Logic | Score |
|---|---|---|
| DDoS | Sliding window: >10 req / 60s, block 300s | +35 |
| Sybil | Age <50 blocks AND freq >8 in 20 blocks | +30 |
| Replay | ZK nullifier registry (bytes32 → bool) | +50 |

Risk levels: **Normal** (0–39) / **Medium** (40–69) / **High** (70–89) / **Critical** (90–100)

### Deployment History

| Version | Address | Gas Used | Change |
|---|---|---|---|
| v1 | `0x0324215d...` | 1,373,180 | — |
| v2 | `0x22311611...` | 1,777,680 | +29.5% |
| v3 (final) | `0x733a81BC...` | 1,387,453 | −21.9% |

### Real Monitoring Log (2026-02-21)
12:23:52 0x00b094... DDoS +35 → 35 [Medium]
12:25:16 0xF6395d... Replay +50 → 50 [Medium]
12:25:16 0xF6395d... Replay +50 → 100 [Critical]
12:38:28 0x00b094... DDoS +35 → 35 [Medium]
12:40:19 0x00b094... Sybil +30 → 65 [High]
12:40:27 0xa05E78... Replay +50 → 50 [Medium]
12:41:26 0xa05E78... Replay +50 → 100 [Critical]
12:41:26 0xa05E78... Replay +50 → 100 [Saturated]


---

## Project Structure
zk-hybrid-defense/
├── src/
│ ├── HybridGuardian.sol # ZK-HHCF main contract
│ ├── ThreatDetector.sol # Threat detection contract
│ ├── RangeProofVerifier.sol # Groth16 verifier
│ └── AttackSimulator.sol # Controlled attack testing
├── circuits/
│ └── range_proof/
│ ├── range_proof.circom
│ ├── input.json
│ ├── proof.json
│ └── public.json
├── python/
│ ├── adaptive_monitor.py # Real-time event monitoring
│ ├── hybrid_submit.py # ZK + CKKS submit pipeline
│ └── diagnose.py # Verifier diagnostics
├── script/
│ ├── Deploy.s.sol
│ ├── DeployThreatDetector.s.sol
│ └── DeploySimulator.s.sol
├── logs/
│ └── threat_monitor.jsonl
└── foundry.toml


---

## Quick Start

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Install Python deps
pip install web3 tenseal==0.3.14

# Build
forge build

# Deploy ThreatDetector
forge script script/DeployThreatDetector.s.sol --rpc-url $RPC_URL --broadcast

# Run monitor
python python/adaptive_monitor.py

# Submit ZK proof
python python/hybrid_submit.py
```

---

## Publications

| Paper | Venue | Status |
|---|---|---|
| ZK-Homomorphic Hybrid Cryptographic Framework for Privacy-Preserving Transaction Verification on Ethereum | ITTA 2026 | Published |
| Adaptive Real-Time Threat Detection for Blockchain Networks | TBD | In preparation |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Smart Contracts | Solidity 0.8.20, Foundry |
| ZK Proofs | Circom 2.0, SnarkJS 0.7, Groth16, bn128 |
| Homomorphic Encryption | TenSEAL 0.3.14, CKKS (poly_mod_degree=8192) |
| Off-chain Monitor | Python 3.11, Web3.py 6.x |
| Blockchain | Ethereum Sepolia, chain ID 11155111 |

---

## Research Context

**Dissertation:** Development of Mechanisms Against Cyber Threats During Information Exchange in Blockchain Networks  
**University:** Azerbaijan Technical University  
**Specialty:** 3339.01  
**Period:** 2022–2026

### Novelty Claims

1. First co-deployment of Groth16 range proof + CKKS-based FHE in a single Ethereum smart contract architecture with a live testnet prototype
2. First unified on-chain detection of DDoS + Sybil + Replay in a single Solidity contract with cumulative reputation scoring
3. Cryptographic integration of ZK nullifiers with threat detection for cross-chain replay prevention
4. 334 KB → 32 bytes on-chain data reduction (10,450x) via keccak256 commitment pattern

---

## License

MIT

---

## Contact

Abdulhuseyn Agayev · Azerbaijan Technical University  
abdulhuseyn.agayev@student.aztu.edu.az  
ORCID: [0000-0003-4930-0672](https://orcid.org/0000-0003-4930-0672)
