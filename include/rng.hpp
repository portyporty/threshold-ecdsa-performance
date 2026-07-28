// Random number generator for the project.
//
// Wraps GMP's gmp_randstate_t (Mersenne Twister by default). This is the
// SAME generator family the existing code used (std::mt19937_64). It is NOT
// cryptographically secure -- a thesis benchmark does not require CSPRNG, and
// reproducibility matters more here. RFC 6979 deterministic nonces remove the
// dependency on randomness from the actual signing path.
//
// Construction options:
//   Rng()         seeded from std::random_device for unpredictable starts
//   Rng(seed)     seeded explicitly so benchmark runs are bit-for-bit reproducible

#pragma once

#include <gmp.h>
#include <gmpxx.h>

#include <cstddef>
#include <cstdint>

namespace tecdsa {

class Rng {
public:
    Rng();
    explicit Rng(uint64_t seed);
    ~Rng();

    Rng(const Rng&) = delete;
    Rng& operator=(const Rng&) = delete;
    Rng(Rng&&) = delete;
    Rng& operator=(Rng&&) = delete;

    // Uniformly random integer in [0, upper_exclusive).
    mpz_class uniform_below(const mpz_class& upper_exclusive);

    // Uniformly random integer in [1, upper_exclusive). Used for nonces and
    // private keys, which the protocol forbids from being zero.
    mpz_class uniform_nonzero_below(const mpz_class& upper_exclusive);

    // Fill `out` with `n` uniformly random bytes.
    void fill_bytes(uint8_t* out, std::size_t n);

private:
    gmp_randstate_t state_;
};

}  // namespace tecdsa
