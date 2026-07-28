#include "secp256k1.hpp"

namespace tecdsa::secp256k1 {

const mpz_class& p() {
    static const mpz_class value(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16);
    return value;
}

const mpz_class& a() {
    static const mpz_class value(0);
    return value;
}

const mpz_class& b() {
    static const mpz_class value(7);
    return value;
}

const mpz_class& gx() {
    static const mpz_class value(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        16);
    return value;
}

const mpz_class& gy() {
    static const mpz_class value(
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        16);
    return value;
}

const mpz_class& n() {
    static const mpz_class value(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16);
    return value;
}

}  // namespace tecdsa::secp256k1
