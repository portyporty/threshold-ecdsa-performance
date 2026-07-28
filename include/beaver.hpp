// Beaver multiplication primitives.
//
// A Beaver triple is a tuple (a, b, c) with c = a * b mod q, where each of
// a, b, c is held additively-shared between two parties. Beaver triples are
// the workhorse of secure two-party multiplication: given shares of x and y,
// they let the parties compute shares of x*y while exchanging only one round
// of "masked" values (d = x - a, e = y - b) that look uniformly random.
//
// In a real protocol the triple is generated in an OFFLINE phase via OT or
// homomorphic encryption so neither party ever learns a, b, or c on its own.
// We simulate the offline phase by sampling centrally; the interesting cost
// for benchmarking is the ONLINE arithmetic (the modular operations in
// beaver_mul), which is identical regardless of how the triple was produced.
//
// Project context: project.pdf section 5 ("Secure Multiplication via Beaver
// Triples") spells out exactly the protocol implemented here.

#pragma once

#include <gmpxx.h>

#include <utility>

#include "rng.hpp"

namespace tecdsa {

// Shares of (a, b, c) where c = a*b mod q.
//   a1 + a2 = a   (mod q)     held by parties 1 and 2 respectively
//   b1 + b2 = b   (mod q)
//   c1 + c2 = a*b (mod q)
struct BeaverTriple {
    mpz_class a1, a2;
    mpz_class b1, b2;
    mpz_class c1, c2;
};

// Generate one fresh triple. Simulates the offline phase: a, b are sampled
// uniformly in [0, q), c = a*b mod q, then each value is split into a
// uniformly random pair of additive shares.
BeaverTriple generate_triple(Rng& rng, const mpz_class& q);

// Compute additive shares of (x1+x2)*(y1+y2) mod q.
// x and y are NEVER reconstructed during this protocol -- the only values
// crossing the wire are d and e, which are uniformly random masks of the
// secret inputs. This is the property that lets the threshold ECDSA online
// phase satisfy Interim Report sec. 4.2.1.
//
// Returns (z1, z2) such that z1 + z2 = (x1+x2)*(y1+y2) mod q.
std::pair<mpz_class, mpz_class> beaver_mul(
    const mpz_class& x1, const mpz_class& x2,
    const mpz_class& y1, const mpz_class& y2,
    const BeaverTriple& triple,
    const mpz_class& q);

}  // namespace tecdsa
