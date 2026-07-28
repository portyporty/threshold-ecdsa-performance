// secp256k1 domain parameters as defined in Standards for Efficient
// Cryptography (SEC 2) and reproduced in Kayra_Thesis.pdf section 1.2.
//
//   Curve:  y^2 = x^3 + a*x + b   (mod p)
//   p     = 2^256 - 2^32 - 977
//   a     = 0
//   b     = 7
//   G     = (Gx, Gy)              -- the base point
//   n     = order of G            -- the group's prime order
//
// Each accessor returns a reference to a static const mpz_class, so the values
// are constructed once per process and reads are cheap thereafter.

#pragma once

#include <gmpxx.h>

namespace tecdsa::secp256k1 {

const mpz_class& p();
const mpz_class& a();
const mpz_class& b();
const mpz_class& gx();
const mpz_class& gy();
const mpz_class& n();

}  // namespace tecdsa::secp256k1
