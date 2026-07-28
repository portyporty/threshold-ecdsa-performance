// Two-of-two threshold ECDSA: end-to-end correctness.
//
// Five layers of checks:
//
//   1. Joint key consistency: Q == skA * skB * G.
//   2. Presign correctness: R == kA * kB * G; sk-shares + k-shares sum to
//      sk and k respectively.
//   3. masked_inverse correctness: (kinv1 + kinv2) == k^{-1} mod n.
//   4. threshold_sign roundtrip: the resulting (r, s) verifies under the
//      joint pubkey via our standard verify().
//   5. The KILLER test: OpenSSL accepts threshold-produced signatures
//      under the joint pubkey. If this passes, the threshold protocol is
//      mathematically indistinguishable from a single-signer ECDSA.
//
// (5) is what proves that the project's MPC implementation is honest:
// the signature on the wire is bit-for-bit a real ECDSA signature, despite
// being produced by two parties without ever reconstructing the private key.

#define OPENSSL_SUPPRESS_DEPRECATED

#include "beaver.hpp"
#include "ec_point.hpp"
#include "ecdsa.hpp"
#include "field.hpp"
#include "rng.hpp"
#include "secp256k1.hpp"
#include "sha256.hpp"
#include "tecdsa.hpp"
#include "test_helpers.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <string>
#include <vector>

using namespace tecdsa;

namespace {

BIGNUM* mpz_to_bn(const mpz_class& x) {
    std::vector<uint8_t> bytes(32, 0);
    if (x != 0) {
        const std::size_t actual = (mpz_sizeinbase(x.get_mpz_t(), 2) + 7) / 8;
        const std::size_t offset = 32 - actual;
        std::size_t written = 0;
        mpz_export(bytes.data() + offset, &written, 1, 1, 1, 0,
                   x.get_mpz_t());
    }
    return BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr);
}

EC_KEY* make_eckey(const AffinePoint& Q) {
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) return nullptr;
    BIGNUM* x = mpz_to_bn(Q.x);
    BIGNUM* y = mpz_to_bn(Q.y);
    const int ok = EC_KEY_set_public_key_affine_coordinates(key, x, y);
    BN_free(x);
    BN_free(y);
    if (!ok) { EC_KEY_free(key); return nullptr; }
    return key;
}

ECDSA_SIG* make_ssig(const Signature& sig) {
    ECDSA_SIG* osig = ECDSA_SIG_new();
    if (!osig) return nullptr;
    BIGNUM* r_bn = mpz_to_bn(sig.r);
    BIGNUM* s_bn = mpz_to_bn(sig.s);
    if (ECDSA_SIG_set0(osig, r_bn, s_bn) == 0) {
        BN_free(r_bn);
        BN_free(s_bn);
        ECDSA_SIG_free(osig);
        return nullptr;
    }
    return osig;
}

}  // namespace

int main() {
    const mpz_class& n = secp256k1::n();
    const mpz_class half_n = n / 2;
    Rng rng(0x7EC05A11ULL);

    // ---- (1) Joint key consistency ----------------------------------------
    for (int i = 0; i < 5; ++i) {
        const ThresholdKey key = threshold_keygen(rng);
        REQUIRE(is_on_curve(key.Q));
        const mpz_class sk_full = mod_mul(key.skA, key.skB, n);
        CHECK(key.Q == scalar_mul(sk_full, generator()));
    }

    // ---- (2) Presign correctness ------------------------------------------
    {
        const ThresholdKey key = threshold_keygen(rng);
        const ThresholdPresign p = threshold_presign(key, rng);

        const mpz_class k_full  = mod_mul(p.kA, p.kB, n);
        const mpz_class sk_full = mod_mul(key.skA, key.skB, n);
        CHECK(p.R == scalar_mul(k_full, generator()));
        CHECK(p.r == (p.R.x % n));
        CHECK(mod_add(p.k1,  p.k2,  n) == k_full);
        CHECK(mod_add(p.sk1, p.sk2, n) == sk_full);
    }

    // ---- (3) masked_inverse correctness -----------------------------------
    for (int i = 0; i < 30; ++i) {
        const mpz_class k  = rng.uniform_nonzero_below(n);
        const mpz_class k1 = rng.uniform_below(n);
        const mpz_class k2 = mod_sub(k, k1, n);

        const BeaverTriple T = generate_triple(rng, n);
        auto [kinv1, kinv2] = masked_inverse(k1, k2, T, rng, n);
        const mpz_class kinv = mod_add(kinv1, kinv2, n);

        CHECK(kinv == mod_inv(k, n));
        CHECK(mod_mul(k, kinv, n) == 1);
    }

    // ---- (4) threshold_sign verifies under joint pubkey via our verify() --
    for (int i = 0; i < 20; ++i) {
        const ThresholdKey key = threshold_keygen(rng);
        const ThresholdPresign p = threshold_presign(key, rng);
        const std::string msg = "threshold sign #" + std::to_string(i);
        const Sha256Hash h = double_sha256(msg);

        const Signature sig = threshold_sign(key, p, h, rng);
        CHECK(sig.r >= 1 && sig.r < n);
        CHECK(sig.s >= 1 && sig.s < n);
        CHECK(sig.s <= half_n);                 // low-s normalized
        CHECK(verify(key.Q, msg, sig.r, sig.s));
    }

    // ---- (5) OpenSSL accepts threshold signatures under joint Q -----------
    for (int i = 0; i < 10; ++i) {
        const ThresholdKey key = threshold_keygen(rng);
        const ThresholdPresign p = threshold_presign(key, rng);
        const std::string msg = "openssl validates 2PC sig #" + std::to_string(i);
        const Sha256Hash h = double_sha256(msg);

        const Signature sig = threshold_sign(key, p, h, rng);

        EC_KEY* eckey = make_eckey(key.Q);
        REQUIRE(eckey != nullptr);
        ECDSA_SIG* osig = make_ssig(sig);
        REQUIRE(osig != nullptr);

        const int ok = ECDSA_do_verify(h.data(),
                                       static_cast<int>(h.size()),
                                       osig, eckey);
        CHECK(ok == 1);

        // Negative control.
        Sha256Hash h_bad = h;
        h_bad[0] ^= 0x01;
        const int bad = ECDSA_do_verify(h_bad.data(),
                                        static_cast<int>(h_bad.size()),
                                        osig, eckey);
        CHECK(bad == 0);

        ECDSA_SIG_free(osig);
        EC_KEY_free(eckey);
    }

    // ---- Tampered message rejects through our standard verify -------------
    {
        const ThresholdKey key = threshold_keygen(rng);
        const ThresholdPresign p = threshold_presign(key, rng);
        const std::string original = "Pay 1 BTC to Alice";
        const std::string tampered = "Pay 1 BTC to Bob";
        const Signature sig = threshold_sign(key, p, double_sha256(original), rng);
        CHECK(verify(key.Q, original, sig.r, sig.s));
        CHECK(!verify(key.Q, tampered, sig.r, sig.s));
    }

    REPORT_AND_RETURN();
}
