// HMAC-SHA-256 and the RFC 6979 deterministic nonce derivation.
//
// HMAC-SHA-256 is the standard H(opad || H(ipad || msg)) construction over
// SHA-256 with block size 64. We need it because RFC 6979 uses HMAC as its
// internal "stretch" primitive when generating k.
//
// RFC 6979 (Pornin, "Deterministic Usage of the DSA and ECDSA") is the
// algorithm that derives the per-signature nonce k as a deterministic
// function of the private key d and the message hash h. This eliminates the
// "duplicate-k" disaster (e.g., the PlayStation 3 exploit) that plagues
// real-world ECDSA implementations.
//
// Kayra_Thesis.pdf section 1.8 recommends RFC 6979 for our project.

#pragma once

#include <gmpxx.h>

#include <cstddef>
#include <cstdint>

#include "sha256.hpp"

namespace tecdsa {

// HMAC-SHA-256 with arbitrary-length key and message. Returns 32-byte MAC.
Sha256Hash hmac_sha256(const uint8_t* key, std::size_t key_len,
                       const uint8_t* msg, std::size_t msg_len);

// Convenience overload when the key is exactly 32 bytes (the common case
// inside RFC 6979, where K is always Sha256Hash-sized).
Sha256Hash hmac_sha256(const Sha256Hash& key,
                       const uint8_t* msg, std::size_t msg_len);

// RFC 6979 section 3.2 deterministic nonce.
//   d : private key, 1 <= d < q
//   h : H(message) -- the same hash that ECDSA will sign over
//   q : group order (n for secp256k1)
// Returns k uniformly determined by (d, h) with 1 <= k < q.
//
// For curves where qlen == hlen (true for secp256k1 + SHA-256, both 256
// bits), the algorithm reduces to a small loop of HMAC calls; we follow the
// specification step-by-step so the implementation is auditable line-by-line
// against the RFC text.
mpz_class derive_nonce(const mpz_class& d,
                       const Sha256Hash& h,
                       const mpz_class& q);

}  // namespace tecdsa
