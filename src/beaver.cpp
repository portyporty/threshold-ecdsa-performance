#include "beaver.hpp"

#include "field.hpp"

namespace tecdsa {

BeaverTriple generate_triple(Rng& rng, const mpz_class& q) {
    BeaverTriple T;

    // Sample the underlying secret triple.
    const mpz_class a = rng.uniform_below(q);
    const mpz_class b = rng.uniform_below(q);
    const mpz_class c = mod_mul(a, b, q);

    // Split each value into a uniformly random pair of additive shares.
    // Picking the first share uniform in [0, q) and setting the second to
    // (value - first) mod q yields a perfectly uniform secret-sharing.
    T.a1 = rng.uniform_below(q);
    T.a2 = mod_sub(a, T.a1, q);
    T.b1 = rng.uniform_below(q);
    T.b2 = mod_sub(b, T.b1, q);
    T.c1 = rng.uniform_below(q);
    T.c2 = mod_sub(c, T.c1, q);

    return T;
}

std::pair<mpz_class, mpz_class> beaver_mul(
    const mpz_class& x1, const mpz_class& x2,
    const mpz_class& y1, const mpz_class& y2,
    const BeaverTriple& T,
    const mpz_class& q) {

    // Step 1. Each party masks its inputs locally with the triple's a, b
    //         shares. d_i = x_i - a_i, e_i = y_i - b_i.
    const mpz_class d1 = mod_sub(x1, T.a1, q);
    const mpz_class d2 = mod_sub(x2, T.a2, q);
    const mpz_class e1 = mod_sub(y1, T.b1, q);
    const mpz_class e2 = mod_sub(y2, T.b2, q);

    // Step 2. Open d = d1+d2  (= x - a)  and  e = e1+e2  (= y - b).
    //         These are safe to reveal: a, b are uniformly random, so d, e
    //         are uniformly random and information-theoretically hide x, y.
    const mpz_class d = mod_add(d1, d2, q);
    const mpz_class e = mod_add(e1, e2, q);

    // Step 3. Each party computes its share of z = x*y locally.
    //   z1 = c1 + d*b1 + e*a1 + d*e
    //   z2 = c2 + d*b2 + e*a2
    // Sum: z1 + z2 = c + d*b + e*a + d*e
    //              = ab + (x-a)b + (y-b)a + (x-a)(y-b) = xy.
    // The d*e term is a public quantity; by convention we tack it onto party 1.
    mpz_class z1 = mod_add(T.c1, mod_mul(d, T.b1, q), q);
    z1 = mod_add(z1, mod_mul(e, T.a1, q), q);
    z1 = mod_add(z1, mod_mul(d, e, q), q);

    mpz_class z2 = mod_add(T.c2, mod_mul(d, T.b2, q), q);
    z2 = mod_add(z2, mod_mul(e, T.a2, q), q);

    return {z1, z2};
}

}  // namespace tecdsa
