// Elliptic curve point operations on secp256k1.
//
// Three layers of checks, in order of strength:
//
//   1. Identity / negation / on-curve sanity  (cheap, catches typos)
//   2. Known-answer tests (KAT): fixed expected coordinates for 2G, 3G, 4G
//      taken from the canonical secp256k1 reference table that every
//      implementation in the world matches. If our point ops match these,
//      the formulas are right.
//   3. Group-law identities checked symbolically over random scalars:
//      nG = O,  (n-1)G = -G,  (a+b)G = aG + bG,  a(bG) = (ab)G.
//      These use random inputs so they catch subtle bugs that pass KATs.

#include "ec_point.hpp"
#include "field.hpp"
#include "rng.hpp"
#include "secp256k1.hpp"
#include "test_helpers.hpp"

#include <iostream>
#include <string>

using tecdsa::AffinePoint;
using tecdsa::generator;
using tecdsa::identity;
using tecdsa::is_on_curve;
using tecdsa::mod_add;
using tecdsa::mod_mul;
using tecdsa::point_add;
using tecdsa::point_double;
using tecdsa::point_neg;
using tecdsa::scalar_mul;

namespace {

AffinePoint make(const std::string& x_hex, const std::string& y_hex) {
    return AffinePoint(mpz_class(x_hex, 16), mpz_class(y_hex, 16));
}

}  // namespace

int main() {
    const AffinePoint G = generator();
    const AffinePoint O = identity();

    // --- Layer 1: structural sanity --------------------------------------
    REQUIRE(is_on_curve(G));
    REQUIRE(O.infinity);
    CHECK(is_on_curve(O));

    // Identity element behaves like one.
    CHECK(point_add(G, O) == G);
    CHECK(point_add(O, G) == G);
    CHECK(point_add(O, O) == O);

    // P + (-P) = O.
    {
        const AffinePoint G_neg = point_neg(G);
        CHECK(is_on_curve(G_neg));
        CHECK(point_add(G, G_neg) == O);
        CHECK(point_neg(G_neg) == G);
        CHECK(point_neg(O) == O);
    }

    // 0*P = O, 1*P = P
    CHECK(scalar_mul(0, G) == O);
    CHECK(scalar_mul(1, G) == G);

    // Doubling consistency: 2*G via scalar_mul == point_double(G).
    CHECK(scalar_mul(2, G) == point_double(G));

    // --- Layer 2: known-answer tests for the first multiples of G --------
    // These coordinates are the canonical reference values for secp256k1
    // (e.g., the SEC 2 standard, Bitcoin Core test fixtures, sage/elliptic).
    {
        const AffinePoint G2_expected = make(
            "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
            "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A");
        CHECK(scalar_mul(2, G) == G2_expected);
        CHECK(point_double(G) == G2_expected);
        CHECK(is_on_curve(G2_expected));
    }
    {
        const AffinePoint G3_expected = make(
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672");
        CHECK(scalar_mul(3, G) == G3_expected);
        CHECK(point_add(G, scalar_mul(2, G)) == G3_expected);
        CHECK(is_on_curve(G3_expected));
    }
    {
        const AffinePoint G4_expected = make(
            "E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13",
            "51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922");
        CHECK(scalar_mul(4, G) == G4_expected);
        CHECK(point_double(scalar_mul(2, G)) == G4_expected);
        CHECK(is_on_curve(G4_expected));
    }
    {
        // 5G is also published. Verifying it nails down that scalar_mul
        // works correctly for an odd scalar > 4 (multi-bit, mixes add+double).
        const AffinePoint G5_expected = make(
            "2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4",
            "D8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6");
        CHECK(scalar_mul(5, G) == G5_expected);
        CHECK(is_on_curve(G5_expected));
    }

    // --- Layer 3: group-law identities at full scale ---------------------
    const mpz_class& n = tecdsa::secp256k1::n();

    // The order of G is n: nG must be O.
    {
        const AffinePoint nG = scalar_mul(n, G);
        CHECK(nG == O);
    }

    // (n-1)G + G == nG == O    =>   (n-1)G == -G.
    {
        const AffinePoint n_minus_1_G = scalar_mul(n - 1, G);
        CHECK(is_on_curve(n_minus_1_G));
        CHECK(point_add(n_minus_1_G, G) == O);
        CHECK(n_minus_1_G == point_neg(G));
    }

    // Random-scalar checks. Reproducible seed so failures replay the same way.
    tecdsa::Rng rng(0xEC0DEULL);
    for (int trial = 0; trial < 20; ++trial) {
        const mpz_class a = rng.uniform_nonzero_below(n);
        const mpz_class b = rng.uniform_nonzero_below(n);

        // (a + b) G == a G + b G
        const AffinePoint lhs1 = scalar_mul(mod_add(a, b, n), G);
        const AffinePoint rhs1 = point_add(scalar_mul(a, G), scalar_mul(b, G));
        CHECK(lhs1 == rhs1);
        CHECK(is_on_curve(lhs1));

        // a (b G) == (a b) G
        const AffinePoint lhs2 = scalar_mul(a, scalar_mul(b, G));
        const AffinePoint rhs2 = scalar_mul(mod_mul(a, b, n), G);
        CHECK(lhs2 == rhs2);
        CHECK(is_on_curve(lhs2));
    }

    REPORT_AND_RETURN();
}
