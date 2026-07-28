// Modular arithmetic over an arbitrary prime modulus m, expressed as free
// functions. Used for both:
//   - the secp256k1 base field Fp  (m = secp256k1::p())
//   - the secp256k1 scalar field Fn (m = secp256k1::n())
//
// All inputs are assumed to already lie in [0, m). All outputs are guaranteed
// to lie in [0, m). Use reduce() if you need to canonicalize an arbitrary
// integer (e.g., a hash output, a negative remainder).
//
// These wrappers are deliberately thin: GMP already provides the heavy lifting
// (Montgomery / Barrett reduction internally for mpz_powm, etc.). The point of
// the wrappers is to give every caller a self-documenting API and to let us
// drop in optimizations later (Montgomery form, lazy reduction) without
// rewriting every site.

#pragma once

#include <cassert>
#include <gmpxx.h>

namespace tecdsa {

// Canonicalize x to [0, m). Handles negatives and values >= m.
inline mpz_class reduce(const mpz_class& x, const mpz_class& m) {
    mpz_class r = x % m;
    if (sgn(r) < 0) r += m;
    return r;
}

inline mpz_class mod_add(const mpz_class& a,
                         const mpz_class& b,
                         const mpz_class& m) {
    mpz_class r = a + b;
    if (r >= m) r -= m;
    return r;
}

inline mpz_class mod_sub(const mpz_class& a,
                         const mpz_class& b,
                         const mpz_class& m) {
    mpz_class r = a - b;
    if (sgn(r) < 0) r += m;
    return r;
}

inline mpz_class mod_neg(const mpz_class& a, const mpz_class& m) {
    if (a == 0) return mpz_class(0);
    return m - a;
}

inline mpz_class mod_mul(const mpz_class& a,
                         const mpz_class& b,
                         const mpz_class& m) {
    return (a * b) % m;
}

// Modular inverse via Extended Euclidean Algorithm (GMP's mpz_invert).
// Asserts gcd(a, m) == 1; in our use cases m is always prime and a is always
// nonzero, so this always succeeds.
inline mpz_class mod_inv(const mpz_class& a, const mpz_class& m) {
    mpz_class r;
    const int ok = mpz_invert(r.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t());
    assert(ok != 0 && "mod_inv: a is not invertible modulo m");
    (void)ok;
    return r;
}

// Modular exponentiation: a^e mod m. GMP picks the right algorithm based on
// the size of e (sliding-window with Montgomery for large exponents).
inline mpz_class mod_pow(const mpz_class& a,
                         const mpz_class& e,
                         const mpz_class& m) {
    mpz_class r;
    mpz_powm(r.get_mpz_t(), a.get_mpz_t(), e.get_mpz_t(), m.get_mpz_t());
    return r;
}

}  // namespace tecdsa
