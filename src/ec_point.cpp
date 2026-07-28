#include "ec_point.hpp"

#include "field.hpp"
#include "secp256k1.hpp"

namespace tecdsa {

bool AffinePoint::operator==(const AffinePoint& other) const {
    if (infinity != other.infinity) return false;
    if (infinity) return true;  // both at infinity
    return x == other.x && y == other.y;
}

AffinePoint identity() {
    AffinePoint P;
    P.infinity = true;
    return P;
}

AffinePoint generator() {
    return AffinePoint(secp256k1::gx(), secp256k1::gy());
}

bool is_on_curve(const AffinePoint& P) {
    if (P.infinity) return true;

    const mpz_class& p = secp256k1::p();
    // y^2 mod p
    const mpz_class lhs = mod_mul(P.y, P.y, p);
    // x^3 + a*x + b mod p  (a = 0 for secp256k1, but compute generically)
    const mpz_class x_sq = mod_mul(P.x, P.x, p);
    const mpz_class x_cu = mod_mul(x_sq, P.x, p);
    const mpz_class ax  = mod_mul(secp256k1::a(), P.x, p);
    const mpz_class rhs = mod_add(mod_add(x_cu, ax, p), secp256k1::b(), p);
    return lhs == rhs;
}

AffinePoint point_neg(const AffinePoint& P) {
    if (P.infinity) return P;
    return AffinePoint(P.x, mod_neg(P.y, secp256k1::p()));
}

AffinePoint point_double(const AffinePoint& P) {
    if (P.infinity) return P;
    const mpz_class& p = secp256k1::p();
    if (P.y == 0) return identity();  // tangent is vertical -> O

    // slope = (3*x^2 + a) / (2*y) mod p   (PDF section 1.4.2)
    const mpz_class three(3);
    const mpz_class two(2);
    const mpz_class x_sq      = mod_mul(P.x, P.x, p);
    const mpz_class three_xsq = mod_mul(three, x_sq, p);
    const mpz_class numerator = mod_add(three_xsq, secp256k1::a(), p);
    const mpz_class denom     = mod_mul(two, P.y, p);
    const mpz_class slope     = mod_mul(numerator, mod_inv(denom, p), p);

    // x_r = slope^2 - 2*x mod p
    const mpz_class slope_sq = mod_mul(slope, slope, p);
    const mpz_class two_x    = mod_mul(two, P.x, p);
    const mpz_class x_r      = mod_sub(slope_sq, two_x, p);

    // y_r = slope * (x - x_r) - y mod p
    const mpz_class x_minus_xr = mod_sub(P.x, x_r, p);
    const mpz_class y_r        = mod_sub(mod_mul(slope, x_minus_xr, p), P.y, p);

    return AffinePoint(x_r, y_r);
}

AffinePoint point_add(const AffinePoint& P, const AffinePoint& Q) {
    if (P.infinity) return Q;
    if (Q.infinity) return P;

    const mpz_class& p = secp256k1::p();

    if (P.x == Q.x) {
        // Same x means either P == Q (use doubling) or P == -Q (sum is O).
        if (P.y == Q.y) {
            return point_double(P);
        }
        return identity();
    }

    // slope = (Q.y - P.y) / (Q.x - P.x) mod p   (PDF section 1.4.1)
    const mpz_class num   = mod_sub(Q.y, P.y, p);
    const mpz_class denom = mod_sub(Q.x, P.x, p);
    const mpz_class slope = mod_mul(num, mod_inv(denom, p), p);

    // x_r = slope^2 - P.x - Q.x mod p
    const mpz_class slope_sq = mod_mul(slope, slope, p);
    const mpz_class sum_x    = mod_add(P.x, Q.x, p);
    const mpz_class x_r      = mod_sub(slope_sq, sum_x, p);

    // y_r = slope * (P.x - x_r) - P.y mod p
    const mpz_class x_minus_xr = mod_sub(P.x, x_r, p);
    const mpz_class y_r        = mod_sub(mod_mul(slope, x_minus_xr, p), P.y, p);

    return AffinePoint(x_r, y_r);
}

AffinePoint scalar_mul(const mpz_class& k, const AffinePoint& P) {
    if (P.infinity) return P;
    if (k == 0) return identity();
    if (sgn(k) < 0) {
        // k * P = (-k) * (-P)  -- needed if a caller ever passes a negative
        // scalar even though our protocol won't.
        return scalar_mul(-k, point_neg(P));
    }

    // Right-to-left double-and-add (PDF section 1.5).
    AffinePoint R = identity();
    AffinePoint Q = P;
    const std::size_t num_bits = mpz_sizeinbase(k.get_mpz_t(), 2);
    for (std::size_t i = 0; i < num_bits; ++i) {
        if (mpz_tstbit(k.get_mpz_t(), i)) {
            R = point_add(R, Q);
        }
        // Skip the final doubling -- Q is unused after the last iteration.
        if (i + 1 < num_bits) {
            Q = point_double(Q);
        }
    }
    return R;
}

}  // namespace tecdsa
