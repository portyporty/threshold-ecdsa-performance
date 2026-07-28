// Two-of-two Threshold ECDSA on secp256k1, DKLs18-style.
//
// This is the protocol from project.pdf:
//
//   Step 1 (Key generation):
//       Alice samples skA, Bob samples skB, both in Z_n.
//       Joint public key Q = skA * skB * G is published; sk = skA * skB
//       is NEVER reconstructed in either party's memory.
//
//   Step 2 (Nonce generation):
//       Each party samples their nonce share kA, kB in Z_n.
//       Joint nonce point R = kA * kB * G is published; r = R.x mod n.
//
//   Step 3 (Secure signing):
//       The parties compute s = k^{-1} * (z + r*sk) mod n via secure
//       two-party computation:
//         (a) additive shares of k^{-1} via masked_inverse (1 Beaver triple)
//         (b) additive shares of z + r*sk locally (r and z are public)
//         (c) additive shares of k^{-1} * (z + r*sk) via beaver_mul
//             (1 Beaver triple)
//         (d) open the resulting s shares.
//
// Output: a STANDARD ECDSA signature (r, s). Mathematically indistinguishable
// from a single-signer ECDSA -- the OpenSSL interop test in test_tecdsa.cpp
// confirms this experimentally.
//
// The benchmark in Phase 5 measures Step 3 (plus the two Beaver triples),
// matching the supervisor's "beaver triplet computation + signature" spec.

#pragma once

#include <gmpxx.h>

#include <utility>

#include "beaver.hpp"
#include "ec_point.hpp"
#include "ecdsa.hpp"
#include "rng.hpp"
#include "sha256.hpp"

namespace tecdsa {

// Long-lived 2-of-2 key material.
struct ThresholdKey {
    mpz_class skA;          // Alice's multiplicative share
    mpz_class skB;          // Bob's   multiplicative share
    AffinePoint Q;          // joint public key Q = skA * skB * G
};

// Per-signature presign state. In a real protocol both parties would
// participate to derive the additive shares of sk and k from their
// multiplicative shares; we simulate centrally because this Phase is a
// CPU benchmark, not a network simulation.
struct ThresholdPresign {
    mpz_class kA, kB;       // multiplicative nonce shares
    AffinePoint R;          // joint nonce point R = kA * kB * G
    mpz_class r;            // r = R.x mod n   (the public part of the sig)
    mpz_class sk1, sk2;     // additive shares of sk = skA * skB
    mpz_class k1, k2;       // additive shares of k  = kA  * kB
};

ThresholdKey      threshold_keygen (Rng& rng);
ThresholdPresign  threshold_presign(const ThresholdKey& key, Rng& rng);

// Compute additive shares of k^{-1} mod q from additive shares of k.
//
// The CRITICAL property compared to the original buggy code: k is NEVER
// reconstructed. The mask r is multiplied with k via a Beaver multiplication;
// only the masked product k*r is opened, and r is fresh so the opened value
// is information-theoretically safe.
//
// Returns (kinv1, kinv2) with kinv1 + kinv2 = k^{-1} mod q.
std::pair<mpz_class, mpz_class> masked_inverse(
    const mpz_class& k1, const mpz_class& k2,
    const BeaverTriple& triple,
    Rng& rng,
    const mpz_class& q);

// Joint two-party signing. Uses TWO Beaver triples internally:
//   - triple #1 inside masked_inverse (computes k^{-1} shares)
//   - triple #2 for the final s = k^{-1} * (z + r*sk) multiplication.
//
// Returns a standard ECDSA Signature (low-s normalized) verifiable under
// the joint public key key.Q with verify() or any compliant verifier.
Signature threshold_sign(const ThresholdKey& key,
                         const ThresholdPresign& presign,
                         const Sha256Hash& h,
                         Rng& rng);

}  // namespace tecdsa
