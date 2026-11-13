// securelink2_selftest.cpp - exercises the six Part C.1 checks for securelink2.cpp.
// Name: Abdul Mohaimin   Student ID: 23i-0652   Assignment: 2
// Build: g++ -std=c++17 -O2 -Wall securelink2_selftest.cpp securelink2.cpp -o selftest -lcrypto
// This is my own test harness (not part of the graded module); its output goes in
// the report as evidence for checks 1-5. Check 6 (source scan) is a grep, below.

#include "securelink2.hpp"
#include <cstdio>
#include <string>
#include <vector>
#include <set>

using namespace sl2;
static int pass = 0, fail = 0;
static void check(const char* what, bool ok) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (ok) ++pass; else ++fail;
}

int main() {
    std::printf("securelink2 self-test\n");

    // Check 1: never NULL, never downgrade.
    std::printf("\nCheck 1 - suite policy (no NULL, no downgrade):\n");
    {
        auto s = strong_suites();
        bool no_null = true; for (auto& x : s) if (x == "NULL") no_null = false;
        check("strong_suites() contains no NULL", no_null);
        check("NULL-only offer is refused (abort)", choose_suite({"NULL"}) == "");
        check("picks AES256 when offered", choose_suite({"AES256-GCM","AES128-GCM","NULL"}) == "AES256-GCM");
        check("picks strongest common (AES128) not NULL", choose_suite({"AES128-GCM","NULL"}) == "AES128-GCM");
        check("empty offer aborts", choose_suite({}) == "");
    }

    // Check 2: KDF, not the raw secret.
    std::printf("\nCheck 2 - key derivation (HKDF, not raw secret):\n");
    {
        std::vector<uint8_t> secret(256, 0); for (size_t i = 0; i < secret.size(); ++i) secret[i] = (uint8_t)(i + 1);
        auto k256 = derive_key(secret, "AES256-GCM", "c2s");
        auto k256b = derive_key(secret, "AES256-GCM", "c2s");
        auto s2c  = derive_key(secret, "AES256-GCM", "s2c");
        auto k128 = derive_key(secret, "AES128-GCM", "c2s");
        check("AES256 key is 32 bytes", k256.size() == 32);
        check("AES128 key is 16 bytes", k128.size() == 16);
        bool not_raw = std::vector<uint8_t>(secret.end() - 32, secret.end()) != k256
                    && std::vector<uint8_t>(secret.begin(), secret.begin() + 32) != k256;
        check("derived key != raw secret bytes", not_raw);
        check("derivation is deterministic", k256 == k256b);
        check("per-direction keys differ (c2s != s2c)", k256 != s2c);
    }

    // Check 3: unique nonce per record.
    std::printf("\nCheck 3 - unique nonce per sequence number:\n");
    {
        std::set<std::vector<uint8_t>> seen; bool uniq = true, len_ok = true;
        for (uint64_t i = 0; i < 100000; ++i) {
            auto n = make_nonce(i);
            if (n.size() != 12) len_ok = false;
            if (!seen.insert(n).second) uniq = false;
        }
        check("nonce is 12 bytes", len_ok);
        check("100000 sequence numbers -> 100000 distinct nonces", uniq);
    }

    // Check 4: AEAD seals and opens correctly.
    std::printf("\nCheck 4 - AEAD round-trip:\n");
    {
        auto key = derive_key(std::vector<uint8_t>(256, 7), "AES256-GCM", "c2s");
        std::string pt = "UNLOCK the front door now";
        auto rec = seal(key, 0, pt);
        check("open(seal(pt)) == pt", open_record(key, rec, 0) == pt);
        auto key128 = derive_key(std::vector<uint8_t>(256, 7), "AES128-GCM", "c2s");
        auto rec128 = seal(key128, 5, pt);
        check("AES128 round-trip at seq 5", open_record(key128, rec128, 5) == pt);
        check("empty plaintext round-trips", open_record(key, seal(key, 9, ""), 9) == "");
    }

    // Check 5: rejects replay / out-of-order / tamper.
    std::printf("\nCheck 5 - replay / reorder / tamper rejected:\n");
    {
        auto key = derive_key(std::vector<uint8_t>(256, 3), "AES256-GCM", "s2c");
        auto rec = seal(key, 7, "STATE LOCKED");
        bool threw;
        threw = false; try { open_record(key, rec, 8); } catch (...) { threw = true; }
        check("wrong expected seqno (replay/reorder) throws", threw);
        threw = false; try { open_record(key, rec, 7); } catch (...) { threw = true; }
        check("correct seqno still opens (no false reject)", !threw);
        auto bad = rec; bad[bad.size() - 1] ^= 0x01;        // flip a tag bit
        threw = false; try { open_record(key, bad, 7); } catch (...) { threw = true; }
        check("tampered ciphertext/tag throws", threw);
        auto bad2 = rec; bad2[0] ^= 0x01;                    // flip the seqno header
        threw = false; try { open_record(key, bad2, 7); } catch (...) { threw = true; }
        check("tampered sequence header throws", threw);
    }

    std::printf("\n==== %d passed, %d failed ====\n", pass, fail);
    return fail ? 1 : 0;
}
