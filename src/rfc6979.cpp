#include "rfc6979.hpp"

#include <cstring>
#include <vector>

namespace tecdsa {

namespace {

constexpr std::size_t kSha256BlockSize = 64;
constexpr std::size_t kSha256OutputSize = 32;  // hlen

// Convert an integer in [0, q) to a fixed-size big-endian byte string of
// length `rolen` (= ceil(qlen/8)). For secp256k1 with qlen=256, rolen=32.
std::vector<uint8_t> int2octets(const mpz_class& x, std::size_t rolen) {
    std::vector<uint8_t> out(rolen, 0);
    if (x == 0) return out;
    const std::size_t actual = (mpz_sizeinbase(x.get_mpz_t(), 2) + 7) / 8;
    const std::size_t offset = rolen - actual;
    std::size_t written = 0;
    mpz_export(out.data() + offset, &written,
               /*order=*/1, /*size=*/1, /*endian=*/1, /*nails=*/0,
               x.get_mpz_t());
    return out;
}

// Take the leftmost qlen bits of `data` and interpret as a big-endian
// integer. For secp256k1+SHA-256 this is a straight 32-byte big-endian
// import; the right-shift handles the general case where hlen > qlen.
mpz_class bits2int(const uint8_t* data, std::size_t len, std::size_t qlen_bits) {
    mpz_class result;
    mpz_import(result.get_mpz_t(), len, 1, 1, 1, 0, data);
    const std::size_t bits_in = len * 8;
    if (bits_in > qlen_bits) {
        result >>= (bits_in - qlen_bits);
    }
    return result;
}

// bits2octets(in) = int2octets(bits2int(in) mod q)
std::vector<uint8_t> bits2octets(const uint8_t* data, std::size_t len,
                                 const mpz_class& q,
                                 std::size_t qlen_bits,
                                 std::size_t rolen) {
    mpz_class z = bits2int(data, len, qlen_bits);
    z %= q;
    return int2octets(z, rolen);
}

}  // namespace

// ---------------------------------------------------------------------------
// HMAC-SHA-256
// ---------------------------------------------------------------------------

Sha256Hash hmac_sha256(const uint8_t* key, std::size_t key_len,
                       const uint8_t* msg, std::size_t msg_len) {
    uint8_t key_block[kSha256BlockSize] = {0};

    // If the key is longer than the block size, replace it with H(key).
    if (key_len > kSha256BlockSize) {
        const Sha256Hash hashed = sha256(key, key_len);
        std::memcpy(key_block, hashed.data(), kSha256OutputSize);
    } else {
        std::memcpy(key_block, key, key_len);
    }

    uint8_t ipad[kSha256BlockSize];
    uint8_t opad[kSha256BlockSize];
    for (std::size_t i = 0; i < kSha256BlockSize; ++i) {
        ipad[i] = static_cast<uint8_t>(key_block[i] ^ 0x36);
        opad[i] = static_cast<uint8_t>(key_block[i] ^ 0x5c);
    }

    // Inner: H(ipad || msg)
    std::vector<uint8_t> inner;
    inner.reserve(kSha256BlockSize + msg_len);
    inner.insert(inner.end(), ipad, ipad + kSha256BlockSize);
    inner.insert(inner.end(), msg, msg + msg_len);
    const Sha256Hash inner_hash = sha256(inner.data(), inner.size());

    // Outer: H(opad || inner_hash)
    std::vector<uint8_t> outer;
    outer.reserve(kSha256BlockSize + kSha256OutputSize);
    outer.insert(outer.end(), opad, opad + kSha256BlockSize);
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return sha256(outer.data(), outer.size());
}

Sha256Hash hmac_sha256(const Sha256Hash& key,
                       const uint8_t* msg, std::size_t msg_len) {
    return hmac_sha256(key.data(), key.size(), msg, msg_len);
}

// ---------------------------------------------------------------------------
// RFC 6979 section 3.2
// ---------------------------------------------------------------------------

mpz_class derive_nonce(const mpz_class& d,
                       const Sha256Hash& h,
                       const mpz_class& q) {
    const std::size_t qlen_bits = mpz_sizeinbase(q.get_mpz_t(), 2);
    const std::size_t rolen     = (qlen_bits + 7) / 8;

    const std::vector<uint8_t> int_d  = int2octets(d, rolen);
    const std::vector<uint8_t> bits_h = bits2octets(h.data(), h.size(), q, qlen_bits, rolen);

    // Step b. V = 0x01 0x01 ... 0x01  (hlen bytes)
    Sha256Hash V;
    V.fill(0x01);

    // Step c. K = 0x00 0x00 ... 0x00  (hlen bytes)
    Sha256Hash K;
    K.fill(0x00);

    // Step d. K = HMAC_K(V || 0x00 || int2octets(d) || bits2octets(h))
    {
        std::vector<uint8_t> buf;
        buf.reserve(kSha256OutputSize + 1 + int_d.size() + bits_h.size());
        buf.insert(buf.end(), V.begin(), V.end());
        buf.push_back(0x00);
        buf.insert(buf.end(), int_d.begin(), int_d.end());
        buf.insert(buf.end(), bits_h.begin(), bits_h.end());
        K = hmac_sha256(K, buf.data(), buf.size());
    }

    // Step e. V = HMAC_K(V)
    V = hmac_sha256(K, V.data(), V.size());

    // Step f. K = HMAC_K(V || 0x01 || int2octets(d) || bits2octets(h))
    {
        std::vector<uint8_t> buf;
        buf.reserve(kSha256OutputSize + 1 + int_d.size() + bits_h.size());
        buf.insert(buf.end(), V.begin(), V.end());
        buf.push_back(0x01);
        buf.insert(buf.end(), int_d.begin(), int_d.end());
        buf.insert(buf.end(), bits_h.begin(), bits_h.end());
        K = hmac_sha256(K, buf.data(), buf.size());
    }

    // Step g. V = HMAC_K(V)
    V = hmac_sha256(K, V.data(), V.size());

    // Step h. Generate candidates until one falls in [1, q-1].
    while (true) {
        std::vector<uint8_t> T;
        T.reserve(rolen);
        while (T.size() < rolen) {
            V = hmac_sha256(K, V.data(), V.size());
            T.insert(T.end(), V.begin(), V.end());
        }
        T.resize(rolen);

        const mpz_class k = bits2int(T.data(), T.size(), qlen_bits);
        if (k >= 1 && k < q) {
            return k;
        }

        // Reject and reseed: K = HMAC_K(V || 0x00); V = HMAC_K(V).
        std::vector<uint8_t> buf;
        buf.reserve(kSha256OutputSize + 1);
        buf.insert(buf.end(), V.begin(), V.end());
        buf.push_back(0x00);
        K = hmac_sha256(K, buf.data(), buf.size());
        V = hmac_sha256(K, V.data(), V.size());
    }
}

}  // namespace tecdsa
