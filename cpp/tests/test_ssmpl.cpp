// SSMPL C++ self-test (in-memory). Build: see CMakeLists.txt.
#include "ssmpl.hpp"
#include <iostream>
#include <cassert>
#include <cstring>

using namespace ssmpl;

static Config cfg_gcm() {
    Config c; c.hash = "SHA-256"; c.iterations = 1000; c.cipher = "AES-256-GCM";
    c.salt = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}; return c;
}
static Config cfg_cbc() {
    Config c; c.hash = "SHA-256"; c.iterations = 1000; c.cipher = "AES-256-CBC-HMAC-SHA256";
    c.salt = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}; return c;
}
static int pass_ = 0, fail_ = 0;
static void check(const char* name, bool cond) {
    if (cond) { pass_++; std::cout << "  ok  " << name << "\n"; }
    else { fail_++; std::cout << "FAIL  " << name << "\n"; }
}
static bool wrong(const Item& it, const std::string& pw, const Config& c) {
    try { decrypt_item(it, pw, c); return false; } catch (...) { return true; }
}

int main() {
    const char* plain = "黄文正文·第一章 secret content";

    std::cout << "# encrypt/decrypt (GCM)\n";
    Config G = cfg_gcm();
    Item it = encrypt_item(plain, "alpha", G);
    check("decrypt correct pw", decrypt_item(it, "alpha", G) == plain);
    check("wrong pw rejected", wrong(it, "nope", G));

    std::cout << "# multi-password (密本, no re-encrypt)\n";
    Item it2 = add_password(it, "beta", "alpha", G);
    check("alpha still works", decrypt_item(it2, "alpha", G) == plain);
    check("beta added works", decrypt_item(it2, "beta", G) == plain);
    check("ct/iv unchanged, books grew", it2.ct == it.ct && it2.iv == it.iv && it2.books.size() == 2);

    std::cout << "# SHA-512\n";
    Config S; S.hash = "SHA-512"; S.iterations = 1500; S.cipher = "AES-256-GCM"; S.salt = G.salt;
    Item is = encrypt_item("你好 world 123", "p1", S);
    check("SHA-512 round-trips", decrypt_item(is, "p1", S) == "你好 world 123");
    check("SHA-512 wrong pw rejected", wrong(is, "zzz", S));

    std::cout << "# CBC + HMAC\n";
    Config C = cfg_cbc();
    Item ic = encrypt_item("cbc data 数据", "cbc1", C);
    check("CBC round-trips", decrypt_item(ic, "cbc1", C) == "cbc data 数据");
    check("CBC wrong pw rejected", wrong(ic, "x", C));

    std::cout << "\n== " << pass_ << " passed, " << fail_ << " failed ==\n";
    return fail_ ? 1 : 0;
}
