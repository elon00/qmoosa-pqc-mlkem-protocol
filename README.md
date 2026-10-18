# QMOOSA Post-Quantum Cryptography Protocol (`qmoosa-pqc-mlkem-protocol`)

[![NIST FIPS 203 Compliant](https://img.shields.io/badge/Standard-NIST%20FIPS%20203-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![Post-Quantum Security](https://img.shields.io/badge/Security-Level%201%2F3%2F5-success.svg)](https://csrc.nist.gov/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`@qmoosa/pqc-mlkem-protocol` is the canonical post-quantum cryptography protocol specification and parameter definition module for the QMOOSA-1000 portfolio (Domain 2: Post-Quantum Cryptography & Quantum Security, Batch 11, Repository 051).

This package implements the exact parameters, algebraic ring structures, types, and mathematical invariants defined by the official **NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)** standard released in August 2024.

---

## NIST FIPS 203 Parameter Sets

| Parameter Set | Module Rank ($k$) | $\eta_1$ | $\eta_2$ | $d_u$ | $d_v$ | Public Key ($ek$) | Private Key ($dk$) | Ciphertext ($c$) | Shared Secret | NIST Security Category |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-512** | 2 | 3 | 2 | 10 | 4 | 800 bytes | 1,632 bytes | 768 bytes | 32 bytes | Category 1 (AES-128) |
| **ML-KEM-768** | 3 | 2 | 2 | 10 | 4 | 1,184 bytes | 2,400 bytes | 1,088 bytes | 32 bytes | Category 3 (AES-192, Primary) |
| **ML-KEM-1024** | 4 | 2 | 2 | 11 | 5 | 1,568 bytes | 3,168 bytes | 1,568 bytes | 32 bytes | Category 5 (AES-256) |

---

## Algebraic Ring Foundation

- **Ring**: $R_q = \mathbb{Z}_q[X] / (X^{256} + 1)$
- **Modulus**: $q = 3329$ (prime)
- **Ring Degree**: $n = 256$
- **NTT Invariant**: $q \equiv 1 \pmod{256}$, with 256th primitive root of unity $\zeta = 17 \pmod{3329}$.

---

## Invariants & Security Guarantees

1. **Defensive Immutability**: All parameter sets are `Object.freeze()` locked to prevent runtime mutation.
2. **Strict Byte-Length Gate**: Enforces exact encapsulation, decapsulation, and ciphertext byte lengths.
3. **Timing Leak Resistance**: Provides constant-time byte array comparison (`constantTimeEqual`).
4. **Hybrid Protocol Readiness**: Defines structures for hybrid classical-PQC key encapsulation combining X25519 with ML-KEM-768.

---

## License

MIT © 2026 elon00 / QMOOSA Mission
