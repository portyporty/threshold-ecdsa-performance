// Elliptic curve point operations for secp256k1 in AFFINE coordinates.
//
// Implements the formulas from Kayra_Thesis.pdf section 1.4 directly:
//
//   y^2 = x^3 + a*x + b   (mod p)         curve equation
//   secp256k1: a = 0, b = 7
//
// Point at infinity is represented by infinity = true with x, y unused.
//
// Affine vs. Jacobian: every point_add and point_double here costs one
// modular inverse (the slope denominator). For a 256-bit scalar mul that's
// ~384 inverses. We start with affine because the supervisor's PDF describes
// affine, the math is auditable line-by-line against the PDF, and we want
// known-good reference numbers before any optimization. If Phase 5 benchmark
// numbers are too slow we'll add Jacobian as a drop-in.

#pragma once

#include <gmpxx.h>

namespace tecdsa {

struct AffinePoint {
    mpz_class x;
    mpz_class y;
    bool infinity;

    AffinePoint() : x(0), y(0), infinity(true) {}
    AffinePoint(mpz_class x_in, mpz_class y_in)
        : x(std::move(x_in)), y(std::move(y_in)), infinity(false) {}

    bool operator==(const AffinePoint& other) const;
    bool operator!=(const AffinePoint& other) const { return !(*this == other); }
};

// The point at infinity (additive identity of the group).
AffinePoint identity();

// secp256k1 generator G = (Gx, Gy).
AffinePoint generator();

// True iff P is the point at infinity OR satisfies y^2 = x^3 + a*x + b mod p.
// This is the cheapest sanity check possible: every operation should produce
// on-curve points if our math is correct.
bool is_on_curve(const AffinePoint& P);

// -P  =  (x, -y mod p)
AffinePoint point_neg(const AffinePoint& P);

// R = P + Q on the curve. Handles all four edge cases: either operand is O,
// P = -Q (sum is O), and P = Q (delegates to point_double).
AffinePoint point_add(const AffinePoint& P, const AffinePoint& Q);

// R = 2P. Returns O when y_P = 0 (the tangent is vertical).
AffinePoint point_double(const AffinePoint& P);

// R = k * P via right-to-left double-and-add (PDF section 1.5).
// Variable-time: timing depends on the bits of k. Acceptable for a CPU
// benchmark; would NOT be acceptable for a production signing implementation.
AffinePoint scalar_mul(const mpz_class& k, const AffinePoint& P);

}  // namespace tecdsa
