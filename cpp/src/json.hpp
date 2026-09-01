// Minimal JSON (for the SSMPL blob format only). Header-only. Not a general-purpose JSON lib.
#ifndef SSMPL_JSON_HPP
#define SSMPL_JSON_HPP
#include <string>
#include <vector>
#include <map>
#include <cstdlib>
#include <cctype>
#include <stdexcept>

struct Json {
    enum Type { Null, Bool, Number, String, Array, Object } type = Null;
    bool b = false; double num = 0; std::string str;
    std::vector<Json> arr;
    std::map<std::string, Json> obj;

    static Json parse(const std::string& s) { size_t i = 0; Json v = parse_value(s, i); return v; }

    const Json* find(const std::string& k) const {
        if (type != Object) return nullptr;
        auto it = obj.find(k); return it == obj.end() ? nullptr : &it->second;
    }
    const Json& at(size_t idx) const { return arr.at(idx); }
    bool is_string() const { return type == String; }
    bool is_object() const { return type == Object; }
    bool is_number() const { return type == Number; }
    size_t size() const { return type == Array ? arr.size() : (type == Object ? obj.size() : 0); }
    double as_number() const { return num; }
    const std::string& as_string() const { return str; }
};

static void skip_ws(const std::string& s, size_t& i) { while (i < s.size() && std::isspace((unsigned char)s[i])) i++; }
static Json parse_value(const std::string& s, size_t& i);
static std::string parse_string(const std::string& s, size_t& i) {
    if (s[i] != '"') throw std::runtime_error("json: expected string");
    i++; std::string out;
    while (i < s.size() && s[i] != '"') {
        char c = s[i++];
        if (c == '\\') {
            char e = s[i++];
            switch (e) { case 'n': out += '\n'; break; case 't': out += '\t'; break; case 'r': out += '\r'; break;
                         case 'b': out += '\b'; break; case 'f': out += '\f'; break; default: out += e; }
        } else out += c;
    }
    i++; // closing quote
    return out;
}
static Json parse_value(const std::string& s, size_t& i) {
    skip_ws(s, i); Json v;
    if (i >= s.size()) throw std::runtime_error("json: EOF");
    char c = s[i];
    if (c == '{') {
        i++; v.type = Json::Object; skip_ws(s, i);
        if (s[i] == '}') { i++; return v; }
        while (true) { skip_ws(s, i); std::string k = parse_string(s, i); skip_ws(s, i); if (s[i] != ':') throw std::runtime_error("json: expected :"); i++; v.obj[k] = parse_value(s, i); skip_ws(s, i); if (s[i] == ',') { i++; continue; } if (s[i] == '}') { i++; break; } throw std::runtime_error("json: expected , or }"); }
    } else if (c == '[') {
        i++; v.type = Json::Array; skip_ws(s, i);
        if (s[i] == ']') { i++; return v; }
        while (true) { v.arr.push_back(parse_value(s, i)); skip_ws(s, i); if (s[i] == ',') { i++; continue; } if (s[i] == ']') { i++; break; } throw std::runtime_error("json: expected , or ]"); }
    } else if (c == '"') { v.type = Json::String; v.str = parse_string(s, i); }
    else if (s.compare(i, 4, "null") == 0) { v.type = Json::Null; i += 4; }
    else if (s.compare(i, 4, "true") == 0) { v.type = Json::Bool; v.b = true; i += 4; }
    else if (s.compare(i, 5, "false") == 0) { v.type = Json::Bool; v.b = false; i += 5; }
    else { v.type = Json::Number; char* end; v.num = std::strtod(s.c_str() + i, &end); i = end - s.c_str(); }
    return v;
}
static std::string json_escape(const std::string& s) {
    std::string o; o += '"';
    for (char c : s) { if (c == '"') o += "\\\""; else if (c == '\\') o += "\\\\"; else if (c == '\n') o += "\\n"; else if (c == '\r') o += "\\r"; else o += c; }
    o += '"'; return o;
}
static std::string to_string(const Json& v) {
    switch (v.type) {
        case Json::Null: return "null";
        case Json::Bool: return v.b ? "true" : "false";
        case Json::Number: { std::string s = std::to_string(v.num); size_t p = s.find('.'); if (p != std::string::npos) { while (!s.empty() && s.back() == '0') s.pop_back(); if (!s.empty() && s.back() == '.') s.pop_back(); } return s; }
        case Json::String: return json_escape(v.str);
        case Json::Array: { std::string o = "["; bool f = true; for (const auto& e : v.arr) { if (!f) o += ","; f = false; o += to_string(e); } return o + "]"; }
        case Json::Object: { std::string o = "{"; bool f = true; for (const auto& kv : v.obj) { if (!f) o += ","; f = false; o += json_escape(kv.first) + ":" + to_string(kv.second); } return o + "}"; }
    }
    return "";
}
#endif
