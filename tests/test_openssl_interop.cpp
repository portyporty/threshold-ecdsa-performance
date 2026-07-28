// OpenSSL interoperability check.
//
// Project Charter / Interim Report sec. 4.2.2 (Correctness):
//   "The output signature must be verifiable by standard libraries
//    (e.g., OpenSSL)."
//
// This is the strongest correctness check the project can run. We sign a
// message with our entire pipeline (double-SHA-256 + RFC 6979 + low-s
// normalization on secp256k1) and hand the resulting (Q, hash, r, s) to
// OpenSSL's ECDSA verifier. If OpenSSL accepts every signature across many
// random key/message pairs, the implementation is byte-for-byte interoperable
// with the reference world.
//
// We use OpenSSL's legacy EC_KEY / ECDSA_SIG APIs (deprecated in OpenSSL 3.x
// but still supported) because they accept raw (r, s) without going through
// DER encoding. OPENSSL_SUPPRESS_DEPRECATED is the official escape hatch for
// downstream code that wants the legacy interface.

#define OPENSSL_SUPPRESS_DEPRECATED

#include "ec_point.hpp"
#include "ecdsa.hpp"
#include "rng.hpp"
#include "secp256k1.hpp"
#include "sha256.hpp"
#include "test_helpers.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <string>
#include <vector>

using namespace tecdsa;

namespace {

// Export an mpz_class as a 32-byte big-endian buffer, then hand it to
// BN_bin2bn so the resulting BIGNUM has the right value.
BIGNUM* mpz_to_bn(const mpz_class& x) {
    std::vector<uint8_t> bytes(32, 0);
    if (x != 0) {
        const std::size_t actual =
            (mpz_sizeinbase(x.get_mpz_t(), 2) + 7) / 8;
        const std::size_t offset = 32 - actual;
        std::size_t written = 0;
        mpz_export(bytes.data() + offset, &written,
                   /*order=*/1, /*size=*/1, /*endian=*/1, /*nails=*/0,
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
    if (!ok) {
        EC_KEY_free(key);
        return nullptr;
    }
    return key;
}

ECDSA_SIG* make_sig(const Signature& sig) {
    ECDSA_SIG* osig = ECDSA_SIG_new();
    if (!osig) return nullptr;
    BIGNUM* r_bn = mpz_to_bn(sig.r);
    BIGNUM* s_bn = mpz_to_bn(sig.s);
    // ECDSA_SIG_set0 takes ownership of the BIGNUMs on success.
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
    Rng rng(0x05AEC0DEULL);

    // Iterate enough that we exercise multiple key bit patterns, several
    // message lengths, and the low-s branch on both sides of n/2.
    for (int i = 0; i < 25; ++i) {
        KeyPair kp = generate_keypair(rng);
        REQUIRE(is_on_curve(kp.Q));

        const std::string msg = "openssl interop iteration #" + std::to_string(i);
        const Signature sig = sign(kp.d, msg);

        // Sanity: our own verifier must accept our own signature first.
        REQUIRE(verify(kp.Q, msg, sig.r, sig.s));

        EC_KEY* eckey = make_eckey(kp.Q);
        REQUIRE(eckey != nullptr);
        ECDSA_SIG* osig = make_sig(sig);
        REQUIRE(osig != nullptr);

        // OpenSSL takes the raw hash that ECDSA signed over.
        const Sha256Hash z_bytes = double_sha256(msg);

        const int result = ECDSA_do_verify(z_bytes.data(),
                                           static_cast<int>(z_bytes.size()),
                                           osig,
                                           eckey);
        CHECK(result == 1);

        // Negative control: tamper with the hash, OpenSSL must reject.
        Sha256Hash z_tampered = z_bytes;
        z_tampered[0] ^= 0x01;
        const int result_tampered = ECDSA_do_verify(z_tampered.data(),
                                                    static_cast<int>(z_tampered.size()),
                                                    osig,
                                                    eckey);
        CHECK(result_tampered == 0);

        ECDSA_SIG_free(osig);
        EC_KEY_free(eckey);
    }

    REPORT_AND_RETURN();
}
