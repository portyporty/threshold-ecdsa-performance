// Paillier homomorphic encryption — GMP implementation.
// See include/paillier.hpp for the public API.

#include "paillier.hpp"

#include "rng.hpp"

#include <gmp.h>
#include <random>
#include <stdexcept>

namespace tecdsa::paillier {

namespace {

// L(u, n) = (u - 1) / n   — exact integer division (Paillier's L-function).
mpz_class L(const mpz_class& u, const mpz_class& n) {
    return (u - 1) / n;
}

void seed_randstate_from_rd(gmp_randstate_t rs) {
    std::random_device rd;
    // Seed with multiple 32-bit draws to reduce collisions.
    mpz_class seed = 0;
    for (int i = 0; i < 8; ++i) {
        seed <<= 32;
        seed += static_cast<unsigned long>(rd());
    }
    gmp_randseed(rs, seed.get_mpz_t());
}

mpz_class pick_r_coprime_to_n(const mpz_class& n, tecdsa::Rng& rng) {
    mpz_class r, g;
    do {
        r = rng.uniform_nonzero_below(n);  // [1, n)
        mpz_gcd(g.get_mpz_t(), r.get_mpz_t(), n.get_mpz_t());
    } while (g != 1);
    return r;
}

}  // namespace

// ---------------------------------------------------------------------------
// Key generation  (mirrors docs/KeyGen.gp)
// ---------------------------------------------------------------------------

KeyPair generate_keys(unsigned int prime_bits) {
    gmp_randstate_t rs;
    gmp_randinit_default(rs);

    // Seed from OS entropy (std::random_device).
    // KeyGen is excluded from the benchmark; we only need correct key sizes.
    seed_randstate_from_rd(rs);

    mpz_class p, q, n;

    // Generate a prime of exactly prime_bits bits.
    auto gen_prime = [&](mpz_class& out) {
        mpz_urandomb(out.get_mpz_t(), rs, prime_bits);
        mpz_setbit(out.get_mpz_t(), prime_bits - 1);  // force top bit
        mpz_nextprime(out.get_mpz_t(), out.get_mpz_t());
        while (mpz_sizeinbase(out.get_mpz_t(), 2) != prime_bits) {
            mpz_urandomb(out.get_mpz_t(), rs, prime_bits);
            mpz_setbit(out.get_mpz_t(), prime_bits - 1);
            mpz_nextprime(out.get_mpz_t(), out.get_mpz_t());
        }
    };

    // Ensure N is exactly (2*prime_bits) bits. Two 1024-bit primes can yield a
    // 2047-bit product; the supervisor's requirement is a full 2048-bit modulus.
    const std::size_t target_n_bits = static_cast<std::size_t>(prime_bits) * 2;
    do {
        gen_prime(p);
        do { gen_prime(q); } while (q == p);
        n = p * q;
    } while (mpz_sizeinbase(n.get_mpz_t(), 2) != target_n_bits);

    gmp_randclear(rs);

    mpz_class n2 = n * n;
    mpz_class g  = n + 1;

    // lambda = lcm(p-1, q-1)
    mpz_class pm1 = p - 1;
    mpz_class qm1 = q - 1;
    mpz_class gcd_pq;
    mpz_gcd(gcd_pq.get_mpz_t(), pm1.get_mpz_t(), qm1.get_mpz_t());
    mpz_class lambda = (pm1 * qm1) / gcd_pq;

    // mu = L(g^lambda mod N^2)^{-1} mod N
    mpz_class u;
    mpz_powm(u.get_mpz_t(), g.get_mpz_t(), lambda.get_mpz_t(),
             n2.get_mpz_t());
    mpz_class Lval = L(u, n);
    mpz_class mu;
    if (mpz_invert(mu.get_mpz_t(), Lval.get_mpz_t(), n.get_mpz_t()) == 0) {
        throw std::runtime_error("paillier: mu inversion failed");
    }

    return KeyPair{
        PublicKey{std::move(n), std::move(g), std::move(n2)},
        PrivateKey{std::move(lambda), std::move(mu)}
    };
}

// ---------------------------------------------------------------------------
// Encryption  (mirrors docs/pencryption.gp)
// ---------------------------------------------------------------------------

mpz_class encrypt(const mpz_class& m, const PublicKey& pk) {
    tecdsa::Rng rng;
    return encrypt(m, pk, rng);
}

mpz_class encrypt(const mpz_class& m, const PublicKey& pk, tecdsa::Rng& rng) {
    if (m < 0 || m >= pk.n) {
        throw std::runtime_error("paillier::encrypt: m out of range [0, N)");
    }

    // Pick random r in [1, N-1] with gcd(r, N) = 1.
    const mpz_class r = pick_r_coprime_to_n(pk.n, rng);

    // c = g^m * r^N  mod N^2
    mpz_class gm, rn;
    mpz_powm(gm.get_mpz_t(), pk.g.get_mpz_t(), m.get_mpz_t(),
             pk.n2.get_mpz_t());
    mpz_powm(rn.get_mpz_t(), r.get_mpz_t(), pk.n.get_mpz_t(),
             pk.n2.get_mpz_t());

    mpz_class c = (gm * rn) % pk.n2;
    return c;
}

// ---------------------------------------------------------------------------
// Decryption  (for test verification only)
// ---------------------------------------------------------------------------

mpz_class decrypt(const mpz_class& c, const PublicKey& pk,
                  const PrivateKey& sk) {
    // m = L(c^lambda mod N^2) * mu  mod N
    mpz_class u;
    mpz_powm(u.get_mpz_t(), c.get_mpz_t(), sk.lambda.get_mpz_t(),
             pk.n2.get_mpz_t());
    mpz_class Lval = L(u, pk.n);
    mpz_class m = (Lval * sk.mu) % pk.n;
    return m;
}

}  // namespace tecdsa::paillier
