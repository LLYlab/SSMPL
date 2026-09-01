// SSMPL implementation (OpenSSL / libcrypto). Mirrors js/src/ssmpl.js and python/ssmpl/core.py.
#include "ssmpl.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

namespace ssmpl {

static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64e(const std::vector<uint8_t>& in) {
    std::string out;
    size_t i = 0, n = in.size();
    while (i + 2 < n) {
        uint32_t v = (uint32_t(in[i]) << 16) | (uint32_t(in[i+1]) << 8) | in[i+2];
        out += B64[(v >> 18) & 63]; out += B64[(v >> 12) & 63];
        out += B64[(v >> 6) & 63]; out += B64[v & 63]; i += 3;
    }
    if (i + 1 == n) { uint32_t v = uint32_t(in[i]) << 16; out += B64[(v>>18)&63]; out += B64[(v>>12)&63]; out += "=="; }
    else if (i + 2 == n) { uint32_t v = (uint32_t(in[i])<<16)|(uint32_t(in[i+1])<<8); out += B64[(v>>18)&63]; out += B64[(v>>12)&63]; out += B64[(v>>6)&63]; out += "="; }
    return out;
}
std::vector<uint8_t> b64d(const std::string& in) {
    int val[256]; for (int i = 0; i < 256; i++) val[i] = -1;
    for (int i = 0; i < 64; i++) val[(unsigned char)B64[i]] = i;
    std::vector<uint8_t> out; uint32_t buf = 0; int bits = 0;
    for (char c : in) { if (c == '=' || c == '\n' || c == '\r') continue; int v = val[(unsigned char)c]; if (v < 0) continue; buf = (buf << 6) | v; bits += 6; if (bits >= 8) { bits -= 8; out.push_back((buf >> bits) & 0xFF); } }
    return out;
}
std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> o(a.size());
    for (size_t i = 0; i < a.size(); i++) o[i] = a[i] ^ b[i];
    return o;
}
static const EVP_MD* md_from_hash(const std::string& h) { return (h == "SHA-512") ? EVP_sha512() : EVP_sha256(); }
static std::vector<uint8_t> pbkdf2(const std::string& pw, const std::vector<uint8_t>& salt, unsigned long iters, const char* hash) {
    const EVP_MD* md = (std::string(hash) == "SHA-512") ? EVP_sha512() : EVP_sha256();
    std::vector<uint8_t> out(32);
    PKCS5_PBKDF2_HMAC(pw.c_str(), (int)pw.size(), salt.data(), (int)salt.size(), (int)iters, md, 32, out.data());
    return out;
}

std::vector<uint8_t> derive_key(const std::string& password, const Config& cfg) {
    return pbkdf2(password, cfg.salt, cfg.iterations, cfg.hash.c_str());
}
static std::vector<uint8_t> mac_key(const std::vector<uint8_t>& K) {
    SHA256_CTX c; SHA256_Init(&c);
    SHA256_Update(&c, K.data(), K.size());
    static const unsigned char label[] = "SSMPL.HMAC";
    SHA256_Update(&c, label, sizeof(label) - 1);
    std::vector<uint8_t> d(SHA256_DIGEST_LENGTH); SHA256_Final(d.data(), &c);
    return d;
}
static std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg) {
    unsigned int len = 0;
    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    HMAC(EVP_sha256(), key.data(), (int)key.size(), msg.data(), msg.size(), out.data(), &len);
    out.resize(len); return out;
}

Item encrypt_bytes(const std::string& plaintext, const std::vector<uint8_t>& K, const Config& cfg) {
    Item it;
    const std::vector<uint8_t> pt(plaintext.begin(), plaintext.end());
    if (cfg.cipher == "AES-256-CBC-HMAC-SHA256") {
        std::vector<uint8_t> iv(16); RAND_bytes(iv.data(), (int)iv.size());
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, K.data(), iv.data());
        std::vector<uint8_t> ct(pt.size() + 16); int len = 0, total = 0;
        EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), (int)pt.size()); total = len;
        EVP_EncryptFinal_ex(ctx, ct.data() + total, &len); total += len;
        ct.resize(total); EVP_CIPHER_CTX_free(ctx);
        std::vector<uint8_t> macIn(iv.begin(), iv.end()); macIn.insert(macIn.end(), ct.begin(), ct.end());
        it.iv = b64e(iv); it.ct = b64e(ct); it.mac = b64e(hmac(mac_key(K), macIn));
    } else { // AES-256-GCM
        std::vector<uint8_t> iv(12); RAND_bytes(iv.data(), (int)iv.size());
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, K.data(), iv.data());
        std::vector<uint8_t> ct(pt.size() + 16); int len = 0, total = 0;
        EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), (int)pt.size()); total = len;
        EVP_EncryptFinal_ex(ctx, ct.data() + total, &len); total += len;
        ct.resize(total);
        std::vector<uint8_t> tag(16); EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        EVP_CIPHER_CTX_free(ctx);
        it.iv = b64e(iv); it.ct = b64e(ct); it.tag = b64e(tag);
    }
    return it;
}
std::string decrypt_bytes(const Item& item, const std::vector<uint8_t>& K, const Config& cfg) {
    std::vector<uint8_t> iv = b64d(item.iv);
    if (cfg.cipher == "AES-256-CBC-HMAC-SHA256") {
        std::vector<uint8_t> ct = b64d(item.ct);
        std::vector<uint8_t> macIn = iv; macIn.insert(macIn.end(), ct.begin(), ct.end());
        if (hmac(mac_key(K), macIn) != b64d(item.mac)) throw std::runtime_error("SSMPL: MAC mismatch (wrong key).");
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, K.data(), iv.data());
        std::vector<uint8_t> pt(ct.size() + 16); int len = 0, total = 0;
        EVP_DecryptUpdate(ctx, pt.data(), &len, ct.data(), (int)ct.size()); total = len;
        if (EVP_DecryptFinal_ex(ctx, pt.data() + total, &len) <= 0) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("SSMPL: bad padding."); }
        total += len; pt.resize(total); EVP_CIPHER_CTX_free(ctx);
        return std::string(pt.begin(), pt.end());
    } else { // AES-256-GCM
        std::vector<uint8_t> ct = b64d(item.ct), tag = b64d(item.tag);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, K.data(), iv.data());
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), tag.data());
        std::vector<uint8_t> pt(ct.size() + 16); int len = 0, total = 0;
        EVP_DecryptUpdate(ctx, pt.data(), &len, ct.data(), (int)ct.size()); total = len;
        if (EVP_DecryptFinal_ex(ctx, pt.data() + total, &len) <= 0) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("SSMPL: wrong key / auth failed."); }
        total += len; pt.resize(total); EVP_CIPHER_CTX_free(ctx);
        return std::string(pt.begin(), pt.end());
    }
}

std::vector<uint8_t> compute_book(const std::vector<uint8_t>& P, const std::vector<uint8_t>& K) { return xor_bytes(P, K); }

static std::vector<uint8_t> unlock_key(const Item& item, const std::vector<uint8_t>& P, const Config& cfg) {
    for (const auto& bk : item.books) {
        std::vector<uint8_t> K = xor_bytes(P, b64d(bk));
        try { decrypt_bytes(item, K, cfg); return K; } catch (...) { /* next 密本 */ }
    }
    return {};
}
Item encrypt_item(const std::string& plaintext, const std::string& password, const Config& cfg) {
    std::vector<uint8_t> K(32); RAND_bytes(K.data(), (int)K.size());
    Item it = encrypt_bytes(plaintext, K, cfg);
    std::vector<uint8_t> P = derive_key(password, cfg);
    it.books.push_back(b64e(compute_book(P, K)));
    return it;
}
std::vector<uint8_t> get_key(const Item& item, const std::string& password, const Config& cfg) {
    return unlock_key(item, derive_key(password, cfg), cfg);
}
std::string decrypt_item(const Item& item, const std::string& password, const Config& cfg) {
    std::vector<uint8_t> K = get_key(item, password, cfg);
    if (K.empty()) throw std::runtime_error("SSMPL: wrong password (no 密本 decrypts).");
    return decrypt_bytes(item, K, cfg);
}
Item add_password(const Item& item, const std::string& new_password, const std::string& unlock_password, const Config& cfg) {
    std::vector<uint8_t> K = get_key(item, unlock_password, cfg);
    if (K.empty()) throw std::runtime_error("SSMPL: unlock_password is wrong.");
    Item it = item;
    std::vector<uint8_t> P = derive_key(new_password, cfg);
    it.books.push_back(b64e(compute_book(P, K)));
    return it;
}
Item remove_password(const Item& item, const std::string& password, const Config& cfg) {
    std::vector<uint8_t> P = derive_key(password, cfg);
    Item it = item; it.books.clear();
    for (const auto& bk : item.books) {
        std::vector<uint8_t> K = xor_bytes(P, b64d(bk));
        bool mine = false;
        try { decrypt_bytes(item, K, cfg); mine = true; } catch (...) {}
        if (!mine) it.books.push_back(bk);
    }
    return it;
}

} // namespace ssmpl
