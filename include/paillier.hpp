// Paillier homomorphic encryption (Phase 6).
//
// Translated from the supervisor's Pari/GP scripts (docs/KeyGen.gp,
// docs/pencryption.gp) into C++/GMP.  Only the operations needed by
// the thesis benchmark are exposed:
//
//   generate_keys()  — Service Provider runs this once (offline).
//   encrypt()        — User encrypts a Beaver share before sending it.
//   decrypt()        — Provided for unit-test round-trip verification only.
//
// Security parameter: p,q are 1024-bit primes  =>  N is 2048-bit
// (>= 112-bit security level, as the supervisor required).

#pragma once

#include <gmpxx.h>

namespace tecdsa {
class Rng;
}

namespace tecdsa::paillier {

struct PublicKey {
    mpz_class n;    // N = p * q   (2048-bit)
    mpz_class g;    // g = N + 1   (standard simplification)
    mpz_class n2;   // N^2         (precomputed for encrypt/decrypt)
};

struct PrivateKey {
    mpz_class lambda;   // lcm(p-1, q-1)
    mpz_class mu;       // L(g^lambda mod N^2)^{-1} mod N
};

struct KeyPair {
    PublicKey  pub;
    PrivateKey priv;
};

// Generate a Paillier key pair with 1024-bit primes (N is 2048-bit).
// Uses GMP's probabilistic prime generator seeded from the project RNG.
// This is the Service Provider's job; its cost is NOT benchmarked.
KeyPair generate_keys(unsigned int prime_bits = 1024);

// Encrypt a plaintext m in [0, N) under the given public key.
// Returns ciphertext c = g^m * r^N  mod N^2   where r is random in Z*_N.
// THIS is the user-side bottleneck we measure.
mpz_class encrypt(const mpz_class& m, const PublicKey& pk);

// Same as encrypt(), but draws r from the provided RNG state.
// Prefer this overload in benchmarks to avoid counting RNG init overhead.
mpz_class encrypt(const mpz_class& m, const PublicKey& pk, tecdsa::Rng& rng);

// Decrypt ciphertext c back to plaintext m.
// m = L(c^lambda mod N^2) * mu  mod N
// Used only in tests to verify encrypt round-trips correctly.
mpz_class decrypt(const mpz_class& c, const PublicKey& pk,
                  const PrivateKey& sk);

}  // namespace tecdsa::paillier
