#include "tecdsa.hpp"

#include <stdexcept>

#include "field.hpp"
#include "secp256k1.hpp"

namespace tecdsa {

ThresholdKey threshold_keygen(Rng& rng) {
    ThresholdKey key;
    const mpz_class& n = secp256k1::n();

    // Each party independently samples their multiplicative share.
    key.skA = rng.uniform_nonzero_below(n);
    key.skB = rng.uniform_nonzero_below(n);

    // Joint public key Q = skA * skB * G.
    // In a real 2PC the joint key is computed without reconstructing sk:
    //   Bob publishes Q_B = skB * G; Alice computes Q = skA * Q_B.
    // The arithmetic cost is the same scalar multiplication either way; for
    // simulation we take the simpler path and time the result identically.
    const mpz_class sk = mod_mul(key.skA, key.skB, n);
    key.Q = scalar_mul(sk, generator());

    return key;
}

ThresholdPresign threshold_presign(const ThresholdKey& key, Rng& rng) {
    ThresholdPresign p;
    const mpz_class& n = secp256k1::n();

    // Multiplicative nonce shares.
    p.kA = rng.uniform_nonzero_below(n);
    p.kB = rng.uniform_nonzero_below(n);

    // Joint nonce point R = kA * kB * G.
    const mpz_class k = mod_mul(p.kA, p.kB, n);
    p.R = scalar_mul(k, generator());
    if (p.R.infinity) {
        // Probability ~ 2^-256; surfaced rather than silently retried so a
        // benchmark would never get stuck in an unlikely retry loop.
        throw std::runtime_error("threshold_presign: R at infinity");
    }
    p.r = p.R.x % n;

    // Convert (skA, skB) and (kA, kB) from multiplicative to additive shares.
    // In a real protocol this would also be a 2PC step (e.g., via a Beaver
    // multiplication of (skA, 0) by (0, skB) on additive shares); here we
    // simulate it centrally.
    const mpz_class sk = mod_mul(key.skA, key.skB, n);

    p.sk1 = rng.uniform_below(n);
    p.sk2 = mod_sub(sk, p.sk1, n);

    p.k1 = rng.uniform_below(n);
    p.k2 = mod_sub(k, p.k1, n);

    return p;
}

std::pair<mpz_class, mpz_class> masked_inverse(
    const mpz_class& k1, const mpz_class& k2,
    const BeaverTriple& triple,
    Rng& rng,
    const mpz_class& q) {

    // 1. Sample additive shares (r1, r2) of a fresh random mask r.
    //    Note that we never compute or store r explicitly -- the protocol
    //    works directly on shares. (Sum r = r1+r2 is also never opened; the
    //    only opened value is k*r in step 3, and that's safe because r is
    //    uniformly random.)
    const mpz_class r1 = rng.uniform_below(q);
    const mpz_class r2 = rng.uniform_below(q);

    // 2. Compute additive shares of m = k * r via Beaver multiplication.
    //    THIS IS THE FIX vs. the original code: k is never reconstructed.
    auto [m1, m2] = beaver_mul(k1, k2, r1, r2, triple, q);

    // 3. Open m. Information-theoretically safe because r is fresh and
    //    uniformly random, so m = k*r is uniformly random in Z_q.
    const mpz_class m = mod_add(m1, m2, q);

    // 4. Public inversion of m.
    const mpz_class m_inv = mod_inv(m, q);

    // 5. Each party multiplies its r-share by the public m_inv.
    //    Sum: (r1 + r2) * m_inv = r * (k * r)^{-1} = k^{-1}.
    const mpz_class kinv1 = mod_mul(r1, m_inv, q);
    const mpz_class kinv2 = mod_mul(r2, m_inv, q);

    return {kinv1, kinv2};
}

namespace {

// Bitcoin's low-s convention. Same logic as in ecdsa.cpp; duplicated here so
// the two modules stay independent of each other's implementation details.
mpz_class normalize_low_s(const mpz_class& s, const mpz_class& n) {
    const mpz_class half_n = n / 2;
    return (s > half_n) ? (n - s) : s;
}

}  // namespace

Signature threshold_sign(const ThresholdKey& key,
                         const ThresholdPresign& presign,
                         const Sha256Hash& h,
                         Rng& rng) {
    (void)key;  // skA/skB intentionally unused: protocol consumes only shares.

    const mpz_class& n = secp256k1::n();
    const mpz_class z = hash_to_scalar(h, n);

    // Step A. Additive shares of r * sk computed locally (r is public).
    const mpz_class r_sk1 = mod_mul(presign.r, presign.sk1, n);
    const mpz_class r_sk2 = mod_mul(presign.r, presign.sk2, n);

    // Step B. Additive shares of z + r*sk. z is public; party 1 absorbs it.
    const mpz_class zd1 = mod_add(z, r_sk1, n);
    const mpz_class zd2 = r_sk2;

    // Step C. Additive shares of k^{-1} via masked inversion (Beaver triple #1).
    const BeaverTriple triple_inv = generate_triple(rng, n);
    auto [kinv1, kinv2] = masked_inverse(presign.k1, presign.k2,
                                         triple_inv, rng, n);

    // Step D. Additive shares of s = k^{-1} * (z + r*sk) via Beaver triple #2.
    const BeaverTriple triple_s = generate_triple(rng, n);
    auto [s1, s2] = beaver_mul(kinv1, kinv2, zd1, zd2, triple_s, n);

    // Step E. Open s.
    mpz_class s = mod_add(s1, s2, n);
    if (s == 0) {
        throw std::runtime_error("threshold_sign: s == 0 (cosmically unlikely)");
    }

    s = normalize_low_s(s, n);
    return Signature{presign.r, s};
}

}  // namespace tecdsa
