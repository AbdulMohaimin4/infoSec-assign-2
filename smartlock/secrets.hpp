// Deterministic per-roll instance secrets (shared by the generator and the
// Part A checker). Everything a grader needs (the small DH group, the device
// exponent, the PIN, the flag, the nonce, the port) is derived from the roll
// number, so each student gets a unique instance and a report is only valid
// against the student's own numbers.

#ifndef SECRETS_HPP
#define SECRETS_HPP

#include <cstdint>
#include <string>
#include <random>
#include <array>
#include "slink.hpp"

namespace secrets {

struct Instance {
    std::string roll, device_name, device_suites, hub_id;
    uint64_t p, g, b, B;
    std::string pin, pin_md5, static_nonce, flag;
    int port;
};

inline uint64_t seed_from(const std::string& roll) {
    unsigned char d[32]; unsigned int n = 0;
    EVP_Digest((const unsigned char*)roll.data(), roll.size(), d, &n, EVP_sha256(), nullptr);
    uint64_t s = 0; for (int i = 0; i < 8; ++i) s = (s << 8) | d[i];
    return s;
}

inline bool is_prime(uint64_t n) {
    if (n < 2) return false;
    for (uint64_t q : {2ull,3ull,5ull,7ull,11ull,13ull,17ull,19ull,23ull,29ull,31ull,37ull}) {
        if (n % q == 0) return n == q;
    }
    uint64_t d = n - 1; int r = 0;
    while ((d & 1) == 0) { d >>= 1; r++; }
    for (uint64_t a : {2ull,3ull,5ull,7ull,11ull,13ull,17ull,19ull,23ull,29ull,31ull,37ull}) {
        uint64_t x = slink::modexp(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool comp = true;
        for (int i = 0; i < r - 1; ++i) { x = slink::mulmod(x, x, n); if (x == n - 1) { comp = false; break; } }
        if (comp) return false;
    }
    return true;
}

inline uint64_t small_prime(std::mt19937_64& rng, int bits) {
    while (true) {
        uint64_t c = (rng() & ((1ull << bits) - 1)) | (1ull << (bits - 1)) | 1ull;
        if (is_prime(c)) return c;
    }
}

inline std::string sha16(const std::string& s) {
    unsigned char d[32]; unsigned int n = 0;
    EVP_Digest((const unsigned char*)s.data(), s.size(), d, &n, EVP_sha256(), nullptr);
    return slink::to_hex(std::vector<uint8_t>(d, d + n));
}

inline Instance derive(const std::string& roll) {
    std::mt19937_64 rng(seed_from(roll));
    Instance in;
    in.roll = roll;
    in.device_name = "smartlock-" + roll + ".local";
    in.device_suites = "AES256-GCM,AES128-GCM,NULL";
    in.hub_id = "home-hub";
    in.p = small_prime(rng, 40);
    in.g = 2;
    in.b = 2 + rng() % (in.p - 3);
    in.B = slink::modexp(in.g, in.b, in.p);
    static const char* words[] = {"summer","dragon","falcon","orange","sunset","matrix",
                                  "copper","violet","cosmic","pepper","turbo","river"};
    in.pin = std::string(words[rng() % 12]) + std::to_string(100 + rng() % 900);
    in.pin_md5 = slink::md5hex(in.pin);
    in.static_nonce = sha16("nonce:" + roll).substr(0, 24);   // 12 bytes
    in.flag = "FLAG{" + sha16("smartlock:" + roll).substr(0, 16) + "}";
    in.port = 9000 + (int)(seed_from(roll) % 500);
    return in;
}

}  // namespace secrets
#endif
