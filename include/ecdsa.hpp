// Standard ECDSA on secp256k1, following Kayra_Thesis.pdf section 1.7.
//
// Conventions hard-wired for the supervisor's spec:
//   - message hash z = double_sha256(message)  mod n   (PDF 1.6)
//   - nonce  k = RFC 6979 deterministic         (PDF 1.8)
//   - low-s  s = min(s, n - s)                  (PDF 1.7.7)
//
// The thin Signature/KeyPair structs are deliberately public so tests, the
// OpenSSL interop check, and the threshold protocol can all see the same
// shapes of (r, s) and (d, Q) without going through accessors.

#pragma once

#include <gmpxx.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "ec_point.hpp"
#include "rng.hpp"
#include "sha256.hpp"

namespace tecdsa {

struct KeyPair {
    mpz_class d;       // private key, 1 <= d < n
    AffinePoint Q;     // public key,  Q = d * G
};

struct Signature {
    mpz_class r;
    mpz_class s;
};

// Sample a random valid private key d in [1, n-1] and derive Q = d*G.
KeyPair generate_keypair(Rng& rng);

// Sign message bytes. Performs double-SHA-256 internally per the PDF.
Signature sign(const mpz_class& d, const uint8_t* msg, std::size_t len);
Signature sign(const mpz_class& d, const std::string& message);

// Verify a signature. Returns false on any failure (range check, hash
// mismatch, point at infinity).
bool verify(const AffinePoint& Q,
            const uint8_t* msg, std::size_t len,
            const mpz_class& r, const mpz_class& s);
bool verify(const AffinePoint& Q,
            const std::string& message,
            const mpz_class& r, const mpz_class& s);

// Lower-level entry point used by the threshold protocol and benchmarks
// when the message hash is already known. `h` is the 32-byte hash that
// went through ECDSA's hash function (typically double-SHA-256). This
// computes z = h mod n internally and feeds h into RFC 6979 unchanged.
Signature sign_with_hash(const mpz_class& d, const Sha256Hash& h);

}  // namespace tecdsa
