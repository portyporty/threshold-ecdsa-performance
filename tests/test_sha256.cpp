// SHA-256 test vectors.
//
//   - Empty string and "abc" come from FIPS 180-4 (the SHA-256 standard).
//   - 56-byte vector "abcdbcdecdef..." is also FIPS 180-4, exercising the
//     padding rule that triggers a second message block.
//   - "hello world" is the canonical Bitcoin example used in many places.
//   - Bitcoin's double_sha256("") matches the well-known reference value.
//   - hash_to_scalar is checked for correct big-endian interpretation against
//     a hand-constructed hash whose integer value we can verify independently.

#include "secp256k1.hpp"
#include "sha256.hpp"
#include "test_helpers.hpp"

#include <iomanip>
#include <sstream>
#include <string>

using tecdsa::double_sha256;
using tecdsa::hash_to_scalar;
using tecdsa::sha256;
using tecdsa::Sha256Hash;

namespace {

std::string to_hex(const Sha256Hash& h) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : h) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

}  // namespace

int main() {
    // FIPS 180-4 vectors.
    CHECK(to_hex(sha256(""))
          == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(to_hex(sha256("abc"))
          == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(to_hex(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
          == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // Common reference value used throughout the Bitcoin ecosystem.
    CHECK(to_hex(sha256("hello world"))
          == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");

    // Bitcoin double-SHA-256 of the empty message.
    CHECK(to_hex(double_sha256(""))
          == "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");

    // double_sha256(x) must equal sha256(sha256(x)).
    {
        const Sha256Hash a = double_sha256("hello world");
        const Sha256Hash b = sha256(sha256("hello world").data(), 32);
        CHECK(a == b);
    }

    // hash_to_scalar reads the hash as a 256-bit big-endian integer.
    // Build a hash whose value we know exactly: 0x00..0001.
    {
        Sha256Hash one_hash{};
        one_hash[31] = 0x01;
        const mpz_class n = tecdsa::secp256k1::n();
        const mpz_class z = hash_to_scalar(one_hash, n);
        CHECK(z == 1);
    }

    // hash_to_scalar should equal hash mod n.
    {
        const Sha256Hash h = sha256("threshold ecdsa benchmark");
        mpz_class as_int;
        mpz_import(as_int.get_mpz_t(), h.size(), 1, 1, 1, 0, h.data());
        const mpz_class n = tecdsa::secp256k1::n();
        CHECK(hash_to_scalar(h, n) == (as_int % n));
    }

    REPORT_AND_RETURN();
}
