// SSMPL CLI (C++ / OpenSSL). Build with CMake (link OpenSSL::Crypto).
//   ssmpl_cli encrypt <password> <plaintextFile> [--hash SHA-256|SHA-512] [--iters N] [--cipher GCM|CBC-HMAC]
//   ssmpl_cli addpass <blob.json> <name> <newPassword> <unlockPassword>
//   ssmpl_cli decrypt <blob.json> <name> <password>
#include "ssmpl.hpp"
#include "json.hpp"
#include <fstream>
#include <iostream>
#include <sstream>

using namespace ssmpl;

static std::string read_file(const std::string& p) {
    std::ifstream f(p, std::ios::binary); std::stringstream ss; ss << f.rdbuf(); return ss.str();
}
static void write_file(const std::string& p, const std::string& s) { std::ofstream f(p, std::ios::binary); f << s; }

static Json item_to_json(const Item& it) {
    Json j; j.type = Json::Object;
    Json iv; iv.type = Json::String; iv.str = it.iv; j.obj["iv"] = iv;
    Json ct; ct.type = Json::String; ct.str = it.ct; j.obj["ct"] = ct;
    if (!it.tag.empty()) { Json t; t.type = Json::String; t.str = it.tag; j.obj["tag"] = t; }
    if (!it.mac.empty()) { Json t; t.type = Json::String; t.str = it.mac; j.obj["mac"] = t; }
    Json books; books.type = Json::Array;
    for (const auto& b : it.books) { Json s; s.type = Json::String; s.str = b; books.arr.push_back(s); }
    j.obj["books"] = books;
    return j;
}
static Item json_to_item(const Json& j) {
    Item it;
    it.iv   = j.find("iv")->as_string();
    it.ct   = j.find("ct")->as_string();
    if (j.find("tag")) it.tag = j.find("tag")->as_string();
    if (j.find("mac")) it.mac = j.find("mac")->as_string();
    if (j.find("books")) for (const auto& b : j.find("books")->arr) it.books.push_back(b.as_string());
    return it;
}
static Config cfg_from_blob(const Json& blob) {
    Config c;
    if (blob.find("hash")) c.hash = blob.find("hash")->as_string();
    if (blob.find("iterations")) c.iterations = (unsigned long)blob.find("iterations")->as_number();
    if (blob.find("cipher")) c.cipher = blob.find("cipher")->as_string();
    if (blob.find("salt")) c.salt = b64d(blob.find("salt")->as_string());
    return c;
}
static std::vector<uint8_t> random_salt() { std::vector<uint8_t> s(16); RAND_bytes(s.data(), 16); return s; }

int main(int argc, char** argv) {
    try {
        std::string cmd = argc > 1 ? argv[1] : "";
        if (cmd == "encrypt") {
            std::string pw = argc > 2 ? argv[2] : "", file = argc > 3 ? argv[3] : "";
            if (pw.empty() || file.empty()) { std::cout << "usage: encrypt <password> <file> [flags]\n"; return 1; }
            Config c; c.hash = "SHA-256"; c.iterations = 250000; c.cipher = "AES-256-GCM"; c.salt = random_salt();
            for (int i = 4; i < argc; i++) {
                if (std::string(argv[i]) == "--hash" && i + 1 < argc) c.hash = argv[++i];
                else if (std::string(argv[i]) == "--iters" && i + 1 < argc) c.iterations = std::stoul(argv[++i]);
                else if (std::string(argv[i]) == "--cipher" && i + 1 < argc) c.cipher = std::string(argv[++i]) == "CBC-HMAC" ? "AES-256-CBC-HMAC-SHA256" : "AES-256-GCM";
            }
            Item it = encrypt_item(read_file(file), pw, c);
            Json blob; blob.type = Json::Object;
            { Json v; v.type = Json::Number; v.num = 1; blob.obj["ssmpl"] = v; }              // ssmpl: 1
            { Json v; v.type = Json::String; v.str = c.cipher; blob.obj["cipher"] = v; }
            { Json v; v.type = Json::String; v.str = "PBKDF2-HMAC"; blob.obj["kdf"] = v; }
            { Json v; v.type = Json::String; v.str = c.hash; blob.obj["hash"] = v; }
            { Json v; v.type = Json::Number; v.num = (double)c.iterations; blob.obj["iterations"] = v; }
            { Json v; v.type = Json::String; v.str = b64e(c.salt); blob.obj["salt"] = v; }
            Json items; items.type = Json::Object;
            { std::string base = file.substr(file.find_last_of("/\\") + 1); items.obj[base] = item_to_json(it); }
            blob.obj["items"] = items;
            write_file("ssmpl-lock.json", to_string(blob) + "\n");
            std::cout << "wrote ssmpl-lock.json  (" << c.hash << "/" << c.iterations << "iters/" << c.cipher << ")\n";
        }
        else if (cmd == "addpass") {
            std::string blobFile = argc > 2 ? argv[2] : "", name = argc > 3 ? argv[3] : "", npw = argc > 4 ? argv[4] : "", unlockpw = argc > 5 ? argv[5] : "";
            Json blob = Json::parse(read_file(blobFile));
            Config c = cfg_from_blob(blob);
            Item it = json_to_item(*blob.find("items")->find(name));
            Item next = add_password(it, npw, unlockpw, c);
            blob.find("items")->obj[name] = item_to_json(next);
            write_file(blobFile, to_string(blob) + "\n");
            std::cout << "added password \"" << npw << "\" to \"" << name << "\" (no re-encryption).\n";
        }
        else if (cmd == "decrypt") {
            std::string blobFile = argc > 2 ? argv[2] : "", name = argc > 3 ? argv[3] : "", pw = argc > 4 ? argv[4] : "";
            Json blob = Json::parse(read_file(blobFile));
            Config c = cfg_from_blob(blob);
            Item it = json_to_item(*blob.find("items")->find(name));
            std::cout << decrypt_item(it, pw, c);
        }
        else std::cout << "SSMPL CLI\n  encrypt <password> <file> [--hash H] [--iters N] [--cipher GCM|CBC-HMAC]\n  addpass <blob.json> <name> <newPw> <unlockPw>\n  decrypt <blob.json> <name> <password>\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << "ERROR: " << e.what() << "\n"; return 1; }
}
