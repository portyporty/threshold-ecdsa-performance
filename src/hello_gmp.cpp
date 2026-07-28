// Phase 0 smoke test.
//
// Verifies three things end-to-end:
//   1. GMP is linked correctly through its C++ wrapper (mpz_class).
//   2. We can represent the secp256k1 field prime exactly, both by parsing
//      its hex form and by computing it from p = 2^256 - 2^32 - 977.
//   3. mpz_powm (modular exponentiation) is reachable, since this is the
//      primitive every modular inverse and Fp exponent will use later.
//
// Exit code 0 = all checks pass. Anything else = setup is broken.

#include <gmpxx.h>

#include <iostream>
#include <string>

namespace {

bool check(bool condition, const std::string& label) {
    std::cout << "  [" << (condition ? "OK  " : "FAIL") << "] " << label << '\n';
    return condition;
}

}  // namespace

int main() {
    std::cout << "GMP version: " << __GNU_MP_VERSION
              << "." << __GNU_MP_VERSION_MINOR
              << "." << __GNU_MP_VERSION_PATCHLEVEL << "\n\n";

    bool all_ok = true;

    // secp256k1 field prime, two independent constructions.
    const mpz_class p_from_def =
        (mpz_class(1) << 256) - (mpz_class(1) << 32) - 977;
    const mpz_class p_from_hex(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

    std::cout << "secp256k1 prime check\n";
    std::cout << "  computed: " << p_from_def.get_str(16) << "\n";
    std::cout << "  parsed  : " << p_from_hex.get_str(16) << "\n";
    all_ok &= check(p_from_def == p_from_hex,
                    "p = 2^256 - 2^32 - 977 matches the literal hex constant");
    all_ok &= check(mpz_sizeinbase(p_from_def.get_mpz_t(), 2) == 256,
                    "p occupies exactly 256 bits");
    std::cout << "\n";

    // Modular exponentiation: 2^(p-1) mod p = 1 by Fermat's little theorem,
    // since p is prime and gcd(2, p) = 1. This sanity-checks both mpz_powm
    // and the primality of our parsed value in one shot.
    std::cout << "Fermat sanity check (2^(p-1) mod p == 1)\n";
    mpz_class one_check;
    mpz_class p_minus_one = p_from_def - 1;
    mpz_powm(one_check.get_mpz_t(),
             mpz_class(2).get_mpz_t(),
             p_minus_one.get_mpz_t(),
             p_from_def.get_mpz_t());
    std::cout << "  result: " << one_check << "\n";
    all_ok &= check(one_check == 1, "secp256k1 p passes Fermat with base 2");
    std::cout << "\n";

    // Modular inverse via mpz_invert -- this is the primitive Field.inv()
    // and Scalar.inv() will both wrap in Phase 1.
    std::cout << "Modular inverse check (a * a^-1 mod p == 1)\n";
    const mpz_class a("123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 16);
    mpz_class a_inv;
    int invertible = mpz_invert(a_inv.get_mpz_t(),
                                a.get_mpz_t(),
                                p_from_def.get_mpz_t());
    all_ok &= check(invertible != 0, "mpz_invert reports a is invertible mod p");
    mpz_class product = (a * a_inv) % p_from_def;
    all_ok &= check(product == 1, "a * a^-1 == 1 mod p");
    std::cout << "\n";

    if (all_ok) {
        std::cout << "Phase 0 smoke test: PASS\n";
        return 0;
    }
    std::cout << "Phase 0 smoke test: FAIL\n";
    return 1;
}
