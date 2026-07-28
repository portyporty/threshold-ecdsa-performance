// Phase 6 tests: Paillier homomorphic encryption correctness.
//
// 1. Key-size check: N must be >= 2048 bits (p,q each >= 1024 bits).
// 2. Encrypt/decrypt round-trip for several plaintexts.
// 3. Homomorphic addition: Dec(Enc(a) * Enc(b) mod N^2) == a + b mod N.
// 4. Scalar multiplication: Dec(Enc(m)^k mod N^2) == k*m mod N.

#include "paillier.hpp"
#include "rng.hpp"
#include "test_helpers.hpp"

#include <gmpxx.h>
#include <iostream>

int main() {
    std::cout << "=== test_paillier ===\n";

    auto kp = tecdsa::paillier::generate_keys(1024);

    // 1. Key size
    const std::size_t n_bits = mpz_sizeinbase(kp.pub.n.get_mpz_t(), 2);
    std::cout << "N bit-length: " << n_bits << "\n";
    CHECK(n_bits >= 2048);
    CHECK(kp.pub.g == kp.pub.n + 1);
    CHECK(kp.pub.n2 == kp.pub.n * kp.pub.n);

    // 2. Encrypt/decrypt round-trip
    {
        tecdsa::Rng rng(0xC0FFEEULL);
        mpz_class m0(0);
        CHECK(tecdsa::paillier::decrypt(
            tecdsa::paillier::encrypt(m0, kp.pub, rng), kp.pub, kp.priv) == m0);

        mpz_class m1(1);
        CHECK(tecdsa::paillier::decrypt(
            tecdsa::paillier::encrypt(m1, kp.pub, rng), kp.pub, kp.priv) == m1);

        mpz_class m42(42);
        CHECK(tecdsa::paillier::decrypt(
            tecdsa::paillier::encrypt(m42, kp.pub, rng), kp.pub, kp.priv) == m42);

        mpz_class big("123456789012345678901234567890");
        CHECK(tecdsa::paillier::decrypt(
            tecdsa::paillier::encrypt(big, kp.pub, rng), kp.pub, kp.priv) == big);

        mpz_class max_val = kp.pub.n - 1;
        CHECK(tecdsa::paillier::decrypt(
            tecdsa::paillier::encrypt(max_val, kp.pub, rng), kp.pub, kp.priv) == max_val);
    }

    // 3. Homomorphic addition:  Dec(Enc(a) * Enc(b) mod N^2) == (a+b) mod N
    {
        tecdsa::Rng rng(0xBEEF1234ULL);
        mpz_class a(12345);
        mpz_class b(67890);
        mpz_class ca = tecdsa::paillier::encrypt(a, kp.pub, rng);
        mpz_class cb = tecdsa::paillier::encrypt(b, kp.pub, rng);
        mpz_class c_sum = (ca * cb) % kp.pub.n2;
        mpz_class decrypted = tecdsa::paillier::decrypt(c_sum, kp.pub, kp.priv);
        CHECK(decrypted == (a + b) % kp.pub.n);
    }

    // 4. Scalar multiplication:  Dec(Enc(m)^k mod N^2) == k*m mod N
    {
        tecdsa::Rng rng(0x12345678ULL);
        mpz_class m(999);
        mpz_class k(7);
        mpz_class cm = tecdsa::paillier::encrypt(m, kp.pub, rng);
        mpz_class c_scaled;
        mpz_powm(c_scaled.get_mpz_t(), cm.get_mpz_t(), k.get_mpz_t(),
                 kp.pub.n2.get_mpz_t());
        mpz_class decrypted = tecdsa::paillier::decrypt(c_scaled, kp.pub, kp.priv);
        CHECK(decrypted == (k * m) % kp.pub.n);
    }

    REPORT_AND_RETURN();
}
