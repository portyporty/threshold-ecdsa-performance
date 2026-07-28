# Threshold ECDSA Performance Analysis

From-scratch **C++17** implementation comparing **standard ECDSA**, Bitcoin-style **2-of-2 multisig**, and **2-of-2 threshold ECDSA** (DKLs18-style MPC) on Bitcoin’s `secp256k1` curve, with an optional **Paillier** homomorphic-encryption confidentiality layer. Arithmetic uses GNU MP (`mpz_class`); correctness is checked against **OpenSSL** as an independent oracle.

Relevant to **custody / fintech** (distributed key control without on-chain multisig scripts) and **defense / high-assurance systems** (threshold signing, share confidentiality, measurable CPU cost).

---

## Headline findings

Numbers from a 1000-iteration run (`gcc 16.1.0`, MSYS2 UCRT64, `-O3`, single core). Absolute times vary by machine; **ratios** are stable.

### Per-scenario timings

| ID | Scenario | mean (ms) | mean (cycles) |
|----|----------|----------:|---------------:|
| A0 | OpenSSL `ECDSA_sign` (calibration) | 0.328 | 818,119 |
| A1 | Standard ECDSA, *s*-phase only (`kG` precomputed) | 0.003 | 6,482 |
| A2 | Standard ECDSA, full sign | 1.164 | 2,903,506 |
| B  | Bitcoin multisig 2-of-2 (two full ECDSA signs) | 2.179 | 5,436,040 |
| C1 | Threshold ECDSA, online phase (presign excluded) | 0.008 | 19,247 |
| C2 | Threshold ECDSA, full pipeline (presign + sign) | 1.053 | 2,625,961 |
| C3 | Threshold online + user-side Paillier `encrypt` | 9.607 | 23,974,063 |

*(A0–C2 from the development machine calibration run; C3 from the 1000-iteration confidentiality run in `bench_summary_1000.md`.)*

### Slowdown factors

| Comparison | Ratio | Interpretation |
|---|---:|---|
| `C2 / A2` | ≈ 0.9× | Full threshold pipeline ≈ standard ECDSA when both include `kG` |
| `C2 / B`  | ≈ 0.5× | Threshold MPC ≈ **half** the CPU cost of native 2-of-2 multisig |
| `C3 / A2` | ≈ **10×** | With Paillier confidentiality, user-side CPU matches the 10×–50× hypothesis |
| `A2 / A0` | ≈ 3.5× | Custom standard ECDSA vs OpenSSL (credibility calibration) |

### Takeaways

1. **`kG` dominates.** Without confidentiality, most of a sign is elliptic-curve scalar multiplication. Threshold moves that work into `presign` and amortises **one** joint `kG` instead of one per signer (unlike Bitcoin multisig).
2. **Beaver online overhead is small** next to `kG` (~3× vs the *s*-phase-only baseline, negligible end-to-end).
3. **Confidentiality is the CPU bottleneck.** Encrypting Beaver shares with 2048-bit Paillier (1024-bit primes) brings the measured user-side cost to ≈ **10×** standard ECDSA — inside the interim-report hypothesis — while network latency was intentionally **out of scope**.
4. **OpenSSL interop** anchors correctness: signatures produced here verify under OpenSSL; tampered hashes are rejected.

---

## Prerequisites

Tested on **MSYS2 / UCRT64** (Windows). Linux works the same way (`libgmp-dev`, `libssl-dev`, `cmake`, `ninja`, `g++`).

### Windows (MSYS2)

```bash
pacman -Syu
pacman -S --needed \
    mingw-w64-ucrt-x86_64-toolchain \
    mingw-w64-ucrt-x86_64-gmp \
    mingw-w64-ucrt-x86_64-openssl \
    mingw-w64-ucrt-x86_64-cmake \
    mingw-w64-ucrt-x86_64-ninja \
    pkgconf
```

Add `C:\msys64\ucrt64\bin` to `PATH`, then verify `g++`, `cmake`, `ninja`, and `pkg-config --modversion gmp`.

---

## Build

```powershell
cmake -S . -B build -G Ninja
cmake --build build
```

Under `build/`:

| Artifact | Role |
|----------|------|
| `libtecdsa_core.a` | Static library (all crypto modules) |
| `hello_gmp.exe` | GMP linkage smoke test |
| `test_*.exe` | Unit / interop tests |
| `bench_all.exe` | Comparison benchmark |

Default build type is **Release (`-O3`)**. Use `-DCMAKE_BUILD_TYPE=Debug` for development.

---

## Test

```powershell
ctest --test-dir build --output-on-failure
```

| Test | Coverage |
|---|---|
| `test_field` | `Fp` / `Fn` axioms over random inputs |
| `test_sha256` | FIPS 180-4 vectors, Bitcoin double-SHA-256 |
| `test_ec` | `secp256k1` known-answer tests and group-law identities |
| `test_rfc6979` | HMAC-SHA-256 + deterministic nonce behaviour |
| `test_ecdsa` | Sign/verify, low-*s*, tamper / wrong-key rejection |
| `test_beaver` | Triple invariant and secure multiplication |
| `test_paillier` | 2048-bit keys, encrypt/decrypt, homomorphic ops |
| `test_openssl_interop` | Our standard ECDSA signatures verified by OpenSSL |
| `test_tecdsa` | Threshold sign → joint pubkey verify + OpenSSL accept/reject |

Expected: **100% tests passed** (9 tests).

---

## Benchmark

```powershell
.\build\bench_all.exe
.\build\bench_all.exe 1000
.\build\bench_all.exe 1000 --md
.\build\bench_all.exe 1000 --csv bench_results.csv
```

| Flag | Effect |
|---|---|
| positional / `-n` / `--iterations` | Iteration count (default 100) |
| `--md` | Markdown summary table |
| `--csv FILE` | Per-iteration CSV |
| `--help` | Usage |

| ID | What is timed |
|----|----------------|
| A0 | OpenSSL `ECDSA_do_sign` (calibration) |
| A1 | Standard ECDSA *s*-phase only (`kG` outside the loop) |
| A2 | Full standard ECDSA (`RFC 6979` + `kG` + low-*s*) |
| B  | Two independent full ECDSA signs (2-of-2 multisig model) |
| C1 | Threshold online phase (presign excluded) |
| C2 | Presign + online (apples-to-apples with A2) |
| C3 | Online phase + one user-side Paillier encryption |

Scope: **single-thread CPU cost only** — no network round-trip simulation.

---

## Modules (short)

- **`field` / `ec_point` / `secp256k1`** — modular arithmetic and affine `secp256k1` ops over GMP.
- **`sha256` / `rfc6979` / `ecdsa`** — Bitcoin-style hashing, deterministic nonces, low-*s* ECDSA.
- **`beaver` / `tecdsa`** — 2-of-2 DKLs18-style threshold signing; `k` and `sk` are never reconstructed in memory (`masked_inverse` via Beaver multiplication).
- **`paillier`** — 2048-bit Paillier (1024-bit primes) for share confidentiality (scenario C3).
- **`bench_util`** — timing, stats, Markdown/CSV exporters.

### Protocol guarantees (threshold path)

Multiplicative shares of the private key and nonce; joint pubkey `Q = skA·skB·G`; joint nonce point via multiplicative nonce shares; `s` assembled with Beaver triples so neither party holds full `sk` or full `k`. Output is a **standard ECDSA signature** under the joint public key.

### RNG note

`Rng` wraps GMP’s Mersenne Twister for reproducible thesis benchmarks. Production deployments should use a CSPRNG; RFC 6979 already removes nonce-quality risk on the standard ECDSA path.

---

## Reproduce the benchmarks

```powershell
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
.\build\bench_all.exe 1000 --md
```

Sample summary from a 1000-iteration run: [`bench_summary_1000.md`](bench_summary_1000.md).

---

## Repository layout

```
threshold-ecdsa-performance/
├── README.md
├── CMakeLists.txt
├── bench_summary_1000.md
├── include/          # public headers
├── src/              # implementations + hello_gmp
├── tests/            # ctest binaries
├── bench/            # bench_all
└── tools/            # export helpers
```

---

## References

1. Doerner, Kondi, Lee, shelat (2018). *Secure Two-party Threshold ECDSA from ECDSA Assumptions.* IEEE S&P 2018 (DKLs18).
2. Pornin, T. (2013). RFC 6979 — Deterministic DSA/ECDSA.
3. NIST FIPS 180-4 — Secure Hash Standard (SHA-256).
4. RFC 2104 / RFC 4231 — HMAC / HMAC-SHA-256 test vectors.
5. SEC 2 v2.0 — `secp256k1` domain parameters.
6. GNU Multiple Precision Arithmetic Library (GMP).
7. OpenSSL `libcrypto` — interop oracle and A0 calibration baseline.
