// SSMPL — Static Site · Multi-Password Lock  (C++ / OpenSSL)
// Password-based key wrapping (密本) for a fully static site.
// Requires OpenSSL 1.1+ (libcrypto). This is the library header; see ssmpl.cpp.
//
// Config (settable):
//   hash       : "SHA-256" | "SHA-512"
//   iterations : unsigned long (KDF cost)
//   cipher     : "AES-256-GCM" | "AES-256-CBC-HMAC-SHA256"
//   salt       : bytes (>=8, public)
#ifndef SSMPL_HPP
#define SSMPL_HPP

#include <string>
#include <vector>
#include <cstdint>

namespace ssmpl {

// A single encrypted item (the JSON object under items["<name>"]).
struct Item {
    std::string iv;    // base64
    std::string ct;    // base64 ciphertext
    std::string tag;   // base64 (GCM auth tag)  -- only for AES-256-GCM
    std::string mac;   // base64 (HMAC-SHA256)   -- only for AES-256-CBC-HMAC-SHA256
    std::vector<std::string> books; // base64 密本, one per authorized password
};

struct Config {
    std::string hash      = "SHA-256";
    unsigned long iterations = 250000;
    std::string cipher    = "AES-256-GCM";
    std::vector<uint8_t> salt;   // must be set (>=8 bytes)
};

// ---- helpers ----
std::string b64e(const std::vector<uint8_t>& in);
std::vector<uint8_t> b64d(const std::string& in);
std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

// ---- one-way KDF: P = PBKDF2(password, salt, iterations, 32) ----
std::vector<uint8_t> derive_key(const std::string& password, const Config& cfg);

// ---- two-way symmetric cipher ----
Item encrypt_bytes(const std::string& plaintext, const std::vector<uint8_t>& K, const Config& cfg);
std::string decrypt_bytes(const Item& item, const std::vector<uint8_t>& K, const Config& cfg);

// ---- 密本 = P XOR K ----
std::vector<uint8_t> compute_book(const std::vector<uint8_t>& P, const std::vector<uint8_t>& K);

// ---- backend operations ----
Item encrypt_item(const std::string& plaintext, const std::string& password, const Config& cfg);
std::vector<uint8_t> get_key(const Item& item, const std::string& password, const Config& cfg); // empty if wrong
std::string decrypt_item(const Item& item, const std::string& password, const Config& cfg);
// append a 密本 for a new password using an existing password to recover K (no re-encryption)
Item add_password(const Item& item, const std::string& new_password, const std::string& unlock_password,
                  const Config& cfg);

} // namespace ssmpl
#endif // SSMPL_HPP
