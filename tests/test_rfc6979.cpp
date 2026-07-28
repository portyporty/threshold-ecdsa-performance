// RFC 6979 deterministic nonce derivation.
//
// Without published secp256k1+SHA-256 vectors in RFC 6979 itself (it lists
// only NIST P-curves), we test the *properties* of the derivation here:
//
//   - same (d, h) -> same k                (determinism)
//   - 1 <= k < n                           (range)
//   - different h -> different k           (sensitive to message)
//   - different d -> different k           (sensitive to key)
//   - HMAC-SHA-256 matches a known answer  (algorithm is correctly assembled)
//
// The cross-implementation correctness check happens later in
// test_openssl_interop.cpp: if our (sign + RFC 6979) produces signatures that
// OpenSSL accepts as valid, the entire pipeline must be correct.

#include "rfc6979.hpp"
#include "secp256k1.hpp"
#include "sha256.hpp"
#include "test_helpers.hpp"

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

using tecdsa::derive_nonce;
using tecdsa::hmac_sha256;
using tecdsa::sha256;
using tecdsa::Sha256Hash;

namespace {

std::string to_hex(const Sha256Hash& h) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : h) oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

}  // namespace

int main() {
    const mpz_class& n = tecdsa::secp256k1::n();

    // ---- HMAC-SHA-256 known-answer test ---------------------------------
    // RFC 4231 section 4.2 test case 1:
    //   key = 0x0b * 20, data = "Hi There"
    //   HMAC-SHA-256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    {
        const uint8_t key[20] = {
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        };
        const std::string data = "Hi There";
        const Sha256Hash mac = hmac_sha256(
            key, sizeof(key),
            reinterpret_cast<const uint8_t*>(data.data()), data.size());
        CHECK(to_hex(mac)
              == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    // RFC 4231 test case 2 (key shorter than block size):
    //   key = "Jefe", data = "what do ya want for nothing?"
    //   HMAC-SHA-256 = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    {
        const std::string key = "Jefe";
        const std::string data = "what do ya want for nothing?";
        const Sha256Hash mac = hmac_sha256(
            reinterpret_cast<const uint8_t*>(key.data()), key.size(),
            reinterpret_cast<const uint8_t*>(data.data()), data.size());
        CHECK(to_hex(mac)
              == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    // RFC 4231 test case 4 (key exactly block size, then truncation case):
    // We'll use the "long key" test (case 6, key longer than block):
    //   key = 0xaa * 131  (longer than 64-byte block)
    //   data = "Test Using Larger Than Block-Size Key - Hash Key First"
    //   HMAC = 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54
    {
        std::vector<uint8_t> key(131, 0xaa);
        const std::string data = "Test Using Larger Than Block-Size Key - Hash Key First";
        const Sha256Hash mac = hmac_sha256(
            key.data(), key.size(),
            reinterpret_cast<const uint8_t*>(data.data()), data.size());
        CHECK(to_hex(mac)
              == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    // ---- RFC 6979 derive_nonce properties --------------------------------

    // Determinism: same (d, h) -> same k, every time.
    {
        const mpz_class d("12345678901234567890ABCDEF1234567890ABCDEF12345678", 16);
        const Sha256Hash h = sha256("test message");
        const mpz_class k1 = derive_nonce(d, h, n);
        const mpz_class k2 = derive_nonce(d, h, n);
        CHECK(k1 == k2);
    }

    // Range: 1 <= k < n.
    {
        const mpz_class d("FEDCBA9876543210", 16);
        const Sha256Hash h = sha256("another message");
        const mpz_class k = derive_nonce(d, h, n);
        CHECK(k >= 1);
        CHECK(k < n);
    }

    // Sensitive to message: same key, different message -> different k.
    {
        const mpz_class d("ABCDEF0123456789", 16);
        const mpz_class k1 = derive_nonce(d, sha256("msg1"), n);
        const mpz_class k2 = derive_nonce(d, sha256("msg2"), n);
        CHECK(k1 != k2);
    }

    // Sensitive to key: same message, different key -> different k.
    {
        const Sha256Hash h = sha256("same message");
        const mpz_class k1 = derive_nonce(mpz_class("100", 16), h, n);
        const mpz_class k2 = derive_nonce(mpz_class("200", 16), h, n);
        CHECK(k1 != k2);
    }

    REPORT_AND_RETURN();
}
