#include "sha256.hpp"

#include <vector>

namespace tecdsa {

namespace {

using u32 = uint32_t;
using u64 = uint64_t;

inline u32 rotr(u32 x, u32 n) {
    return (x >> n) | (x << (32 - n));
}

constexpr u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

}  // namespace

Sha256Hash sha256(const uint8_t* data, std::size_t len) {
    u32 h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    // Build the padded message in a heap buffer once (small allocation, single
    // pass). For benchmarks the input lengths are tiny (32-byte hashes) so the
    // copy cost is negligible.
    std::vector<uint8_t> buf(data, data + len);
    const u64 bitlen = static_cast<u64>(len) * 8;
    buf.push_back(0x80);
    while (buf.size() % 64 != 56) buf.push_back(0x00);
    for (int i = 7; i >= 0; --i) {
        buf.push_back(static_cast<uint8_t>(bitlen >> (i * 8)));
    }

    for (std::size_t chunk = 0; chunk < buf.size(); chunk += 64) {
        u32 w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<u32>(buf[chunk + 4 * i]) << 24) |
                   (static_cast<u32>(buf[chunk + 4 * i + 1]) << 16) |
                   (static_cast<u32>(buf[chunk + 4 * i + 2]) << 8) |
                   static_cast<u32>(buf[chunk + 4 * i + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const u32 s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const u32 s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        u32 a = h[0], b = h[1], c = h[2], d = h[3];
        u32 e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            const u32 S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const u32 ch = (e & f) ^ ((~e) & g);
            const u32 temp1 = hh + S1 + ch + K[i] + w[i];
            const u32 S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const u32 maj = (a & b) ^ (a & c) ^ (b & c);
            const u32 temp2 = S0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    Sha256Hash out{};
    for (int i = 0; i < 8; ++i) {
        out[4 * i]     = static_cast<uint8_t>(h[i] >> 24);
        out[4 * i + 1] = static_cast<uint8_t>(h[i] >> 16);
        out[4 * i + 2] = static_cast<uint8_t>(h[i] >> 8);
        out[4 * i + 3] = static_cast<uint8_t>(h[i]);
    }
    return out;
}

Sha256Hash sha256(const std::string& msg) {
    return sha256(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

Sha256Hash double_sha256(const uint8_t* data, std::size_t len) {
    const Sha256Hash first = sha256(data, len);
    return sha256(first.data(), first.size());
}

Sha256Hash double_sha256(const std::string& msg) {
    return double_sha256(reinterpret_cast<const uint8_t*>(msg.data()),
                         msg.size());
}

mpz_class hash_to_scalar(const Sha256Hash& hash, const mpz_class& n) {
    // Treat the 32-byte hash as a big-endian 256-bit unsigned integer.
    mpz_class z;
    mpz_import(z.get_mpz_t(),
               hash.size(),
               /*order=*/1,    // most significant word first
               /*size=*/1,     // one byte per "word"
               /*endian=*/1,   // most significant byte first within a word
               /*nails=*/0,    // no skipped bits
               hash.data());
    z %= n;
    return z;
}

}  // namespace tecdsa
