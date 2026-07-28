#include "rng.hpp"

#include <algorithm>
#include <random>

namespace tecdsa {

Rng::Rng() {
    gmp_randinit_default(state_);
    std::random_device rd;
    const uint64_t seed =
        (static_cast<uint64_t>(rd()) << 32) | static_cast<uint64_t>(rd());
    gmp_randseed_ui(state_, seed);
}

Rng::Rng(uint64_t seed) {
    gmp_randinit_default(state_);
    gmp_randseed_ui(state_, seed);
}

Rng::~Rng() {
    gmp_randclear(state_);
}

mpz_class Rng::uniform_below(const mpz_class& upper_exclusive) {
    mpz_class r;
    mpz_urandomm(r.get_mpz_t(), state_, upper_exclusive.get_mpz_t());
    return r;
}

mpz_class Rng::uniform_nonzero_below(const mpz_class& upper_exclusive) {
    mpz_class r;
    do {
        mpz_urandomm(r.get_mpz_t(), state_, upper_exclusive.get_mpz_t());
    } while (r == 0);
    return r;
}

void Rng::fill_bytes(uint8_t* out, std::size_t n) {
    if (n == 0) return;

    // Generate exactly 8*n random bits, then export as big-endian bytes.
    // mpz_export only writes the minimum number of significant bytes, so we
    // pre-zero the buffer and place the result aligned to the right.
    mpz_class r;
    mpz_urandomb(r.get_mpz_t(), state_, n * 8);

    std::fill(out, out + n, static_cast<uint8_t>(0));
    const std::size_t actual_bytes =
        (mpz_sizeinbase(r.get_mpz_t(), 2) + 7) / 8;
    if (actual_bytes == 0) return;  // r happened to be exactly zero

    const std::size_t offset = n - actual_bytes;
    std::size_t written = 0;
    mpz_export(out + offset, &written,
               /*order=*/1, /*size=*/1, /*endian=*/1, /*nails=*/0,
               r.get_mpz_t());
}

}  // namespace tecdsa
