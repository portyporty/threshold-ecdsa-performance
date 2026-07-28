#include "ecdsa.hpp"

#include <stdexcept>

#include "field.hpp"
#include "rfc6979.hpp"
#include "secp256k1.hpp"
#include "sha256.hpp"

namespace tecdsa {

namespace {

// Bitcoin's low-s convention (PDF 1.7.7). Maps every valid signature into
// the canonical lower half of the group, eliminating signature malleability.
mpz_class normalize_low_s(const mpz_class& s, const mpz_class& n) {
    const mpz_class half_n = n / 2;
    return (s > half_n) ? (n - s) : s;
}

}  // namespace

KeyPair generate_keypair(Rng& rng) {
    KeyPair kp;
    kp.d = rng.uniform_nonzero_below(secp256k1::n());
    kp.Q = scalar_mul(kp.d, generator());
    return kp;
}

Signature sign_with_hash(const mpz_class& d, const Sha256Hash& h) {
    const mpz_class& n = secp256k1::n();

    // z = h interpreted as integer, reduced mod n  (PDF 1.6).
    const mpz_class z = hash_to_scalar(h, n);

    // RFC 6979 takes the raw hash bytes, not z (which has already been
    // reduced). For secp256k1+SHA-256 the two are usually identical, but the
    // RFC's bits2octets is defined over the full hash so we hand it `h`.
    const mpz_class k = derive_nonce(d, h, n);

    // R = k * G,  r = R.x mod n
    const AffinePoint R = scalar_mul(k, generator());
    const mpz_class r = R.x % n;
    if (r == 0) {
        // Probability ~ 2^-256. RFC 6979 nonces are deterministic, so the
        // standard "pick a fresh k" advice doesn't apply directly; we surface
        // the condition rather than loop forever or silently fail.
        throw std::runtime_error("ECDSA sign: r == 0 (cosmically unlikely)");
    }

    // s = k^-1 * (z + r*d) mod n
    const mpz_class k_inv     = mod_inv(k, n);
    const mpz_class rd        = mod_mul(r, d, n);
    const mpz_class z_plus_rd = mod_add(z, rd, n);
    mpz_class s = mod_mul(k_inv, z_plus_rd, n);
    if (s == 0) {
        throw std::runtime_error("ECDSA sign: s == 0 (cosmically unlikely)");
    }

    s = normalize_low_s(s, n);
    return Signature{r, s};
}

Signature sign(const mpz_class& d, const uint8_t* msg, std::size_t len) {
    const Sha256Hash h = double_sha256(msg, len);
    return sign_with_hash(d, h);
}

Signature sign(const mpz_class& d, const std::string& message) {
    return sign(d, reinterpret_cast<const uint8_t*>(message.data()),
                message.size());
}

bool verify(const AffinePoint& Q,
            const uint8_t* msg, std::size_t len,
            const mpz_class& r, const mpz_class& s) {
    const mpz_class& n = secp256k1::n();

    // Range check: 1 <= r, s < n  (PDF 1.7 implicitly).
    if (r < 1 || r >= n) return false;
    if (s < 1 || s >= n) return false;

    const Sha256Hash h = double_sha256(msg, len);
    const mpz_class z = hash_to_scalar(h, n);

    const mpz_class w  = mod_inv(s, n);
    const mpz_class u1 = mod_mul(z, w, n);
    const mpz_class u2 = mod_mul(r, w, n);

    // X = u1*G + u2*Q
    const AffinePoint X1 = scalar_mul(u1, generator());
    const AffinePoint X2 = scalar_mul(u2, Q);
    const AffinePoint X  = point_add(X1, X2);
    if (X.infinity) return false;

    // Accept iff r ≡ X.x mod n.
    return (X.x % n) == r;
}

bool verify(const AffinePoint& Q,
            const std::string& message,
            const mpz_class& r, const mpz_class& s) {
    return verify(Q,
                  reinterpret_cast<const uint8_t*>(message.data()),
                  message.size(),
                  r, s);
}

}  // namespace tecdsa
