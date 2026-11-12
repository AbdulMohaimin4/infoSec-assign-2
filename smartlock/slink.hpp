// SmartLock v1 shared protocol helpers (C++17 / OpenSSL). Header only.
//
// A deliberately weak protocol between a smart lock (device, server) and a home
// hub (controller, client), over plain TCP, for CS3002 Assignment 2 (v3, C++).
// Do NOT use any of this as a model for a real system.
//
// Wire framing: one message per line. Fields are separated by TAB, and each
// field is key:value. Values are decimal, hex, or base64 (none contain a TAB or
// a colon), so a packet capture shows the whole handshake in clear text.

#ifndef SLINK_HPP
#define SLINK_HPP

#include <cstdint>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <unistd.h>
#include <openssl/evp.h>

namespace slink {

// ---- small helpers -------------------------------------------------------
inline std::string to_hex(const std::vector<uint8_t>& b) {
    static const char* h = "0123456789abcdef";
    std::string s; s.reserve(b.size() * 2);
    for (uint8_t c : b) { s.push_back(h[c >> 4]); s.push_back(h[c & 15]); }
    return s;
}
inline std::vector<uint8_t> from_hex(const std::string& s) {
    auto v = [](char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; };
    std::vector<uint8_t> b; b.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) b.push_back((v(s[i]) << 4) | v(s[i + 1]));
    return b;
}
inline std::string b64enc(const std::string& in) {
    std::string out((in.size() + 2) / 3 * 4, '\0');
    int n = EVP_EncodeBlock((unsigned char*)out.data(), (const unsigned char*)in.data(), (int)in.size());
    out.resize(n); return out;
}
inline std::string b64dec(const std::string& in) {
    std::string out(in.size() / 4 * 3 + 3, '\0');
    int n = EVP_DecodeBlock((unsigned char*)out.data(), (const unsigned char*)in.data(), (int)in.size());
    if (n < 0) return "";
    // trim padding bytes
    int pad = 0; for (auto it = in.rbegin(); it != in.rend() && *it == '='; ++it) pad++;
    out.resize(n - pad); return out;
}
inline std::string digest(const std::string& in, const EVP_MD* md) {
    unsigned char d[64]; unsigned int n = 0;
    EVP_Digest((const unsigned char*)in.data(), in.size(), d, &n, md, nullptr);
    return to_hex(std::vector<uint8_t>(d, d + n));
}
inline std::string md5hex(const std::string& s) { return digest(s, EVP_md5()); }

// ---- modular exponentiation for the (small) v1 DH group ------------------
inline uint64_t mulmod(uint64_t a, uint64_t b, uint64_t m) {
    return (uint64_t)((__uint128_t)a * b % m);
}
inline uint64_t modexp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t r = 1 % mod; base %= mod;
    while (exp) { if (exp & 1) r = mulmod(r, base, mod); base = mulmod(base, base, mod); exp >>= 1; }
    return r;
}

// ---- suites --------------------------------------------------------------
inline int suite_strength(const std::string& s) {
    if (s == "AES256-GCM") return 3;
    if (s == "AES128-GCM") return 2;
    if (s == "NULL") return 0;
    return -1;
}
inline int suite_keylen(const std::string& s) {
    if (s == "AES256-GCM") return 32;
    if (s == "AES128-GCM") return 16;
    return 0;
}

// v1 derives the record key straight from the raw shared secret (no KDF).
inline std::vector<uint8_t> session_key(uint64_t shared, const std::string& suite) {
    int kl = suite_keylen(suite);
    std::vector<uint8_t> k(kl, 0);
    for (int i = kl - 1; i >= 0 && shared; --i) { k[i] = shared & 0xff; shared >>= 8; }
    return k;
}

// ---- AES-GCM via EVP -----------------------------------------------------
inline std::vector<uint8_t> record_encrypt(const std::string& suite, const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& nonce, const std::string& pt) {
    if (suite == "NULL") return std::vector<uint8_t>(pt.begin(), pt.end());
    const EVP_CIPHER* c = suite == "AES256-GCM" ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, c, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());
    std::vector<uint8_t> out(pt.size()); int len = 0;
    EVP_EncryptUpdate(ctx, out.data(), &len, (const unsigned char*)pt.data(), (int)pt.size());
    int outl = len; EVP_EncryptFinal_ex(ctx, out.data() + len, &len); outl += len;
    out.resize(outl);
    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);
    out.insert(out.end(), tag.begin(), tag.end());   // ciphertext || tag
    return out;
}
inline std::string record_decrypt(const std::string& suite, const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ctin) {
    if (suite == "NULL") return std::string(ctin.begin(), ctin.end());
    if (ctin.size() < 16) throw std::runtime_error("short record");
    const EVP_CIPHER* c = suite == "AES256-GCM" ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    size_t clen = ctin.size() - 16;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, c, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());
    std::vector<uint8_t> out(clen); int len = 0;
    EVP_DecryptUpdate(ctx, out.data(), &len, ctin.data(), (int)clen);
    int outl = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)(ctin.data() + clen));
    int ok = EVP_DecryptFinal_ex(ctx, out.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ok <= 0) throw std::runtime_error("auth tag check failed");
    out.resize(outl + len);
    return std::string(out.begin(), out.end());
}

// ---- line framing --------------------------------------------------------
using Msg = std::map<std::string, std::string>;

inline void send_msg(int fd, const Msg& m) {
    std::string line; bool first = true;
    for (auto& kv : m) { if (!first) line += '\t'; first = false; line += kv.first + ":" + kv.second; }
    line += '\n';
    (void)!write(fd, line.data(), line.size());
}

struct Reader {
    int fd; std::string buf;
    explicit Reader(int f) : fd(f) {}
    bool recv(Msg& out) {
        size_t nl;
        while ((nl = buf.find('\n')) == std::string::npos) {
            char tmp[4096]; ssize_t n = read(fd, tmp, sizeof tmp);
            if (n <= 0) return false;
            buf.append(tmp, n);
        }
        std::string line = buf.substr(0, nl); buf.erase(0, nl + 1);
        out.clear();
        std::stringstream ss(line); std::string field;
        while (std::getline(ss, field, '\t')) {
            size_t c = field.find(':');
            if (c != std::string::npos) out[field.substr(0, c)] = field.substr(c + 1);
        }
        return true;
    }
};

// ---- a tiny key=value config reader (the instance file) ------------------
inline std::map<std::string, std::string> read_config(const std::string& path) {
    std::map<std::string, std::string> cfg;
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open instance file: " + path);
    std::string line;
    while (std::getline(f, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        auto trim = [](std::string& s){ while(!s.empty()&&(s.front()==' '))s.erase(s.begin()); while(!s.empty()&&(s.back()==' '||s.back()=='\r'))s.pop_back(); };
        trim(k); trim(v);
        cfg[k] = v;
    }
    return cfg;
}

}  // namespace slink
#endif
