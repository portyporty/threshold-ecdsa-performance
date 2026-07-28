// SHA-256 and the helpers ECDSA needs on top of it.
//
// We keep our own implementation (rather than linking OpenSSL or BoringSSL)
// because the project charter explicitly contrasts this work with "pre-compiled
// black-box crypto libraries". This file is the carve-out where the project
// owns the entire signing path end-to-end.
//
// double_sha256 is the Bitcoin convention from Kayra_Thesis.pdf section 1.6:
//     h = SHA256(SHA256(message))
// The single-pass variant is exposed too because RFC 6979 (deterministic
// nonces, used in ecdsa.hpp later) needs raw SHA-256 inside HMAC.

#pragma once

#include <gmpxx.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace tecdsa {

using Sha256Hash = std::array<uint8_t, 32>;

Sha256Hash sha256(const uint8_t* data, std::size_t len);
Sha256Hash sha256(const std::string& msg);

Sha256Hash double_sha256(const uint8_t* data, std::size_t len);
Sha256Hash double_sha256(const std::string& msg);

// Interpret the 32-byte hash as a big-endian integer and reduce it modulo n.
// This is the conversion z = h mod n described in section 1.6 of the PDF.
mpz_class hash_to_scalar(const Sha256Hash& hash, const mpz_class& n);

}  // namespace tecdsa
