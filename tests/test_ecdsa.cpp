// Standard ECDSA: sign / verify roundtrip + protocol invariants.
//
// We exercise:
//
//   - Roundtrip: sign(d, m) followed by verify(Q, m, sig) returns true.
//   - Tamper detection: a single bit flipped in the message rejects.
//   - Tamper detection: signature with the wrong public key rejects.
//   - Determinism: with RFC 6979 nonces, sign(d, m) produces the same
//     (r, s) every time.
//   - Low-s convention: every produced s satisfies s <= n/2.
//   - Sanity range checks are honored: signatures with r=0 or r>=n reject.
//
// Cross-implementation correctness goes through the OpenSSL interop test
// in test_openssl_interop.cpp.

#include "ec_point.hpp"
#include "ecdsa.hpp"
#include "rng.hpp"
#include "secp256k1.hpp"
#include "test_helpers.hpp"

#include <string>

using tecdsa::AffinePoint;
using tecdsa::generate_keypair;
using tecdsa::is_on_curve;
using tecdsa::KeyPair;
using tecdsa::Rng;
using tecdsa::Signature;
using tecdsa::sign;
using tecdsa::verify;

int main() {
    Rng rng(0xECD5A11ULL);
    const mpz_class& n = tecdsa::secp256k1::n();
    const mpz_class half_n = n / 2;

    // Roundtrip across many random keys and messages.
    for (int i = 0; i < 30; ++i) {
        KeyPair kp = generate_keypair(rng);
        REQUIRE(is_on_curve(kp.Q));
        const std::string msg = "ECDSA test message #" + std::to_string(i);

        const Signature sig = sign(kp.d, msg);
        CHECK(sig.r >= 1 && sig.r < n);
        CHECK(sig.s >= 1 && sig.s < n);
        CHECK(sig.s <= half_n);  // low-s convention
        CHECK(verify(kp.Q, msg, sig.r, sig.s));
    }

    // Tampered message must fail.
    {
        KeyPair kp = generate_keypair(rng);
        const std::string original = "Pay 1 BTC to Alice";
        const std::string tampered = "Pay 1 BTC to Bob";
        const Signature sig = sign(kp.d, original);
        CHECK(verify(kp.Q, original, sig.r, sig.s));
        CHECK(!verify(kp.Q, tampered, sig.r, sig.s));
    }

    // Wrong public key must fail.
    {
        KeyPair alice = generate_keypair(rng);
        KeyPair eve   = generate_keypair(rng);
        const std::string msg = "From Alice";
        const Signature sig = sign(alice.d, msg);
        CHECK(verify(alice.Q, msg, sig.r, sig.s));
        CHECK(!verify(eve.Q, msg, sig.r, sig.s));
    }

    // Determinism: same input, same signature.
    {
        KeyPair kp = generate_keypair(rng);
        const std::string msg = "RFC 6979 means signatures are pure functions";
        const Signature a = sign(kp.d, msg);
        const Signature b = sign(kp.d, msg);
        CHECK(a.r == b.r);
        CHECK(a.s == b.s);
    }

    // Out-of-range signature components must reject.
    {
        KeyPair kp = generate_keypair(rng);
        const std::string msg = "range check";
        const Signature sig = sign(kp.d, msg);

        CHECK(!verify(kp.Q, msg, mpz_class(0), sig.s));   // r = 0
        CHECK(!verify(kp.Q, msg, sig.r, mpz_class(0)));   // s = 0
        CHECK(!verify(kp.Q, msg, n, sig.s));              // r = n
        CHECK(!verify(kp.Q, msg, sig.r, n));              // s = n
        CHECK(!verify(kp.Q, msg, n + 1, sig.s));          // r > n
    }

    // Mutation of either r or s in a valid signature rejects.
    {
        KeyPair kp = generate_keypair(rng);
        const std::string msg = "do not malleate me";
        const Signature sig = sign(kp.d, msg);
        CHECK(!verify(kp.Q, msg, sig.r + 1, sig.s));
        CHECK(!verify(kp.Q, msg, sig.r, sig.s + 1));
    }

    REPORT_AND_RETURN();
}
