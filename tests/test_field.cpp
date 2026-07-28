// Property-based tests for the modular arithmetic in field.hpp.
//
// We exercise both moduli that the rest of the project depends on:
//   - secp256k1::p() - the base field prime
//   - secp256k1::n() - the scalar (group order) prime
// against the field axioms: identity, commutativity, associativity,
// distributivity, additive and multiplicative inverses, plus Fermat's little
// theorem as a single-shot proof of primality and mod_pow correctness.
//
// Seed is fixed so failures are reproducible from the test binary alone.

#include "field.hpp"
#include "rng.hpp"
#include "secp256k1.hpp"
#include "test_helpers.hpp"

#include <iostream>
#include <string>

using tecdsa::Rng;
using tecdsa::mod_add;
using tecdsa::mod_inv;
using tecdsa::mod_mul;
using tecdsa::mod_neg;
using tecdsa::mod_pow;
using tecdsa::mod_sub;
using tecdsa::reduce;

namespace {

constexpr int kIterations = 200;

void test_reduce_canonicalization(Rng& rng, const mpz_class& m) {
    // Already-canonical inputs are returned unchanged.
    for (int i = 0; i < kIterations; ++i) {
        const mpz_class x = rng.uniform_below(m);
        CHECK(reduce(x, m) == x);
    }

    // Larger-than-m inputs reduce into [0, m) and preserve x mod m.
    for (int i = 0; i < kIterations; ++i) {
        const mpz_class x = rng.uniform_below(m * m);
        const mpz_class r = reduce(x, m);
        CHECK(r >= 0);
        CHECK(r < m);
        CHECK((x - r) % m == 0);
    }

    // Negatives are mapped to their positive representative.
    for (int i = 0; i < kIterations; ++i) {
        const mpz_class x = rng.uniform_nonzero_below(m);
        CHECK(reduce(-x, m) == m - x);
    }

    // Idempotence: reducing twice gives the same answer.
    for (int i = 0; i < kIterations; ++i) {
        const mpz_class x = rng.uniform_below(m * m);
        const mpz_class once = reduce(x, m);
        CHECK(reduce(once, m) == once);
    }
}

void test_field_axioms(Rng& rng, const mpz_class& m, const std::string& label) {
    std::cout << "Field axioms over " << label << '\n';

    const mpz_class zero(0);
    const mpz_class one(1);

    for (int i = 0; i < kIterations; ++i) {
        const mpz_class a = rng.uniform_below(m);
        const mpz_class b = rng.uniform_below(m);
        const mpz_class c = rng.uniform_below(m);

        // Outputs are canonical.
        CHECK(mod_add(a, b, m) < m);
        CHECK(mod_sub(a, b, m) < m);
        CHECK(mod_mul(a, b, m) < m);

        // Identity.
        CHECK(mod_add(a, zero, m) == a);
        CHECK(mod_mul(a, one, m) == a);
        CHECK(mod_mul(a, zero, m) == zero);

        // Commutativity.
        CHECK(mod_add(a, b, m) == mod_add(b, a, m));
        CHECK(mod_mul(a, b, m) == mod_mul(b, a, m));

        // Associativity.
        CHECK(mod_add(mod_add(a, b, m), c, m) ==
              mod_add(a, mod_add(b, c, m), m));
        CHECK(mod_mul(mod_mul(a, b, m), c, m) ==
              mod_mul(a, mod_mul(b, c, m), m));

        // Distributivity: a*(b+c) == a*b + a*c (mod m).
        CHECK(mod_mul(a, mod_add(b, c, m), m) ==
              mod_add(mod_mul(a, b, m), mod_mul(a, c, m), m));

        // Additive inverse: (a - b) + b == a.
        CHECK(mod_add(mod_sub(a, b, m), b, m) == a);

        // mod_neg consistent with mod_sub from zero.
        CHECK(mod_neg(a, m) == mod_sub(zero, a, m));

        // Multiplicative inverse and Fermat (only valid when a != 0 and m prime).
        if (a != 0) {
            const mpz_class a_inv = mod_inv(a, m);
            CHECK(mod_mul(a, a_inv, m) == one);
            CHECK(mod_pow(a, m - 1, m) == one);
        }
    }
}

}  // namespace

int main() {
    Rng rng(0xC0FFEEULL);

    test_reduce_canonicalization(rng, tecdsa::secp256k1::p());
    test_reduce_canonicalization(rng, tecdsa::secp256k1::n());
    test_field_axioms(rng, tecdsa::secp256k1::p(), "Fp (secp256k1 base field)");
    test_field_axioms(rng, tecdsa::secp256k1::n(), "Fn (secp256k1 scalar field)");

    REPORT_AND_RETURN();
}
