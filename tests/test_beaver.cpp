// Beaver triple generation + Beaver multiplication.
//
// Three layers of checks:
//
//   - Triple invariant: for every generated triple,
//       (a1+a2) * (b1+b2) == (c1+c2)  mod q
//     and every share lies in [0, q).
//
//   - Beaver-mul correctness: for many random secrets x, y split into
//     additive shares, the protocol's output shares (z1, z2) satisfy
//     z1 + z2 == x*y mod q.
//
//   - Edge cases: x = 0, y = 1 split as (1, 0), share-permutation symmetry.

#include "beaver.hpp"
#include "field.hpp"
#include "rng.hpp"
#include "secp256k1.hpp"
#include "test_helpers.hpp"

using tecdsa::beaver_mul;
using tecdsa::BeaverTriple;
using tecdsa::generate_triple;
using tecdsa::mod_add;
using tecdsa::mod_mul;
using tecdsa::mod_sub;
using tecdsa::Rng;

int main() {
    const mpz_class& n = tecdsa::secp256k1::n();
    Rng rng(0xBEA7E12EULL);

    // ---- Triple invariant -------------------------------------------------
    for (int i = 0; i < 50; ++i) {
        const BeaverTriple T = generate_triple(rng, n);

        const mpz_class a = mod_add(T.a1, T.a2, n);
        const mpz_class b = mod_add(T.b1, T.b2, n);
        const mpz_class c = mod_add(T.c1, T.c2, n);
        CHECK(mod_mul(a, b, n) == c);

        // Every share is canonical (in [0, n)).
        CHECK(T.a1 < n); CHECK(T.a2 < n);
        CHECK(T.b1 < n); CHECK(T.b2 < n);
        CHECK(T.c1 < n); CHECK(T.c2 < n);
    }

    // ---- Beaver multiplication correctness on random shares ---------------
    for (int i = 0; i < 50; ++i) {
        const mpz_class x = rng.uniform_below(n);
        const mpz_class y = rng.uniform_below(n);

        const mpz_class x1 = rng.uniform_below(n);
        const mpz_class x2 = mod_sub(x, x1, n);
        const mpz_class y1 = rng.uniform_below(n);
        const mpz_class y2 = mod_sub(y, y1, n);

        const BeaverTriple T = generate_triple(rng, n);
        auto [z1, z2] = beaver_mul(x1, x2, y1, y2, T, n);
        const mpz_class z = mod_add(z1, z2, n);
        CHECK(z == mod_mul(x, y, n));
    }

    // ---- Edge case: x = 0 (both shares zero) ------------------------------
    {
        const mpz_class y = rng.uniform_below(n);
        const mpz_class y1 = rng.uniform_below(n);
        const mpz_class y2 = mod_sub(y, y1, n);
        const BeaverTriple T = generate_triple(rng, n);
        auto [z1, z2] = beaver_mul(mpz_class(0), mpz_class(0), y1, y2, T, n);
        CHECK(mod_add(z1, z2, n) == 0);
    }

    // ---- Edge case: y = 1 (split as (1, 0)) -> z = x ----------------------
    {
        const mpz_class x = rng.uniform_below(n);
        const mpz_class x1 = rng.uniform_below(n);
        const mpz_class x2 = mod_sub(x, x1, n);
        const BeaverTriple T = generate_triple(rng, n);
        auto [z1, z2] = beaver_mul(x1, x2, mpz_class(1), mpz_class(0), T, n);
        CHECK(mod_add(z1, z2, n) == x);
    }

    // ---- Symmetry: swapping the two parties' shares produces the same z --
    {
        const mpz_class x1 = rng.uniform_below(n);
        const mpz_class x2 = rng.uniform_below(n);
        const mpz_class y1 = rng.uniform_below(n);
        const mpz_class y2 = rng.uniform_below(n);
        const BeaverTriple T = generate_triple(rng, n);

        auto [z1a, z2a] = beaver_mul(x1, x2, y1, y2, T, n);
        // Swap each input pair; sum should still match (x1+x2)(y1+y2).
        auto [z1b, z2b] = beaver_mul(x2, x1, y2, y1, T, n);
        CHECK(mod_add(z1a, z2a, n) == mod_add(z1b, z2b, n));
    }

    REPORT_AND_RETURN();
}
