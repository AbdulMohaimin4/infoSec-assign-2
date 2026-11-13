// securelink2.cpp - SmartLock v2 record and policy module (the security core).
// Name: Abdul Mohaimin   Student ID: 23i-0652   Assignment: 2
//
// This module is the corrected answer to the five Part A weaknesses:
//   * choose_suite()/strong_suites() never offer or select NULL and never
//     downgrade -> defeats the negotiation downgrade (A1).
//   * derive_key() runs the Diffie-Hellman secret through HKDF-SHA256 (a proper
//     key derivation function), with a per-direction label, instead of using the
//     raw secret as the key -> defeats the no-KDF keying weakness (A3). Combined
//     with the scaffold's fresh 2048-bit ephemeral DH, this also gives forward
//     secrecy.
//   * make_nonce() produces a unique 96-bit nonce for every sequence number, so
//     no (key, nonce) pair is ever reused -> defeats nonce reuse (A4).
//   * seal()/open_record() are AEAD (AES-GCM) that bind the per-record sequence
//     number as associated data and transmit it; open_record() rejects any record
//     whose sequence number is not the expected next one -> defeats replay and
//     reordering (A5) and any tampering (the GCM tag fails).
//
// Record wire format produced by seal() / parsed by open_record():
//     seqno (8 bytes, big-endian)  ||  ciphertext  ||  GCM tag (16 bytes)
// The suite (hence key length) is inferred from the key: 32 bytes = AES256-GCM,
// 16 bytes = AES128-GCM.

#include "securelink2.hpp"
#include <cstring>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

namespace sl2 {

// ---- suite policy --------------------------------------------------------
// Only strong AEAD suites, strongest first. NULL is never present.
std::vector<std::string> strong_suites() {
    return { "AES256-GCM", "AES128-GCM" };
}

// Pick the strongest suite both sides support; "" (abort) rather than downgrade.
// NULL is never selectable because it is not in strong_suites().
std::string choose_suite(const std::vector<std::string>& hub_offer) {
    for (const auto& want : strong_suites())              // our order = our preference
        for (const auto& have : hub_offer)
            if (want == have) return want;
    return "";
}

// ---- key derivation (HKDF-SHA256, not the raw secret) --------------------
// hkdf: extract-and-expand the DH secret into a uniformly random record key,
// bound to a fixed protocol salt and a per-direction info label (context).
static std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& ikm,
                                        const std::string& info, size_t out_len) {
    static const unsigned char salt[] = "SmartLock-v2 record key";
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) throw std::runtime_error("HKDF unavailable");
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[5]; int i = 0;
    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)"SHA256", 0);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                      (void*)ikm.data(), ikm.size());
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                      (void*)salt, sizeof(salt) - 1);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                      (void*)info.data(), info.size());
    params[i++] = OSSL_PARAM_construct_end();

    std::vector<uint8_t> out(out_len);
    int ok = EVP_KDF_derive(ctx, out.data(), out_len, params);
    EVP_KDF_CTX_free(ctx);
    if (ok <= 0) throw std::runtime_error("HKDF derive failed");
    return out;
}

std::vector<uint8_t> derive_key(const std::vector<uint8_t>& shared_secret,
                                const std::string& suite, const std::string& context) {
    int kl = keylen(suite);
    if (kl == 0) throw std::runtime_error("derive_key: unknown suite");
    if (shared_secret.empty()) throw std::runtime_error("derive_key: empty secret");
    return hkdf_sha256(shared_secret, context, (size_t)kl);
}

// ---- per-record nonce ----------------------------------------------------
// 96-bit nonce = 4 zero bytes || 64-bit big-endian sequence number. Unique for
// every sequence number under a key, so GCM's (key, nonce) pair is never reused.
std::vector<uint8_t> make_nonce(uint64_t seqno) {
    std::vector<uint8_t> n(12, 0);
    for (int i = 0; i < 8; ++i) n[11 - i] = (uint8_t)((seqno >> (8 * i)) & 0xff);
    return n;
}

// ---- AEAD helpers --------------------------------------------------------
static const EVP_CIPHER* cipher_for(size_t keylen_bytes) {
    if (keylen_bytes == 32) return EVP_aes_256_gcm();
    if (keylen_bytes == 16) return EVP_aes_128_gcm();
    throw std::runtime_error("unsupported key length");
}
static void put_seq_be(uint8_t out[8], uint64_t seqno) {
    for (int i = 0; i < 8; ++i) out[7 - i] = (uint8_t)((seqno >> (8 * i)) & 0xff);
}
static uint64_t get_seq_be(const uint8_t in[8]) {
    uint64_t s = 0;
    for (int i = 0; i < 8; ++i) s = (s << 8) | in[i];
    return s;
}

// seal: AES-GCM encrypt, with the sequence number as associated data (so it is
// authenticated) and transmitted in the clear as the record header.
std::vector<uint8_t> seal(const std::vector<uint8_t>& key, uint64_t seqno,
                          const std::string& plaintext) {
    const EVP_CIPHER* c = cipher_for(key.size());
    std::vector<uint8_t> nonce = make_nonce(seqno);
    uint8_t aad[8]; put_seq_be(aad, seqno);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("cipher ctx");
    std::vector<uint8_t> ct(plaintext.size());
    std::vector<uint8_t> tag(16);
    try {
        if (EVP_EncryptInit_ex(ctx, c, nullptr, nullptr, nullptr) != 1) throw std::runtime_error("init");
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1) throw std::runtime_error("ivlen");
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) throw std::runtime_error("key");
        int len = 0;
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad, sizeof aad) != 1) throw std::runtime_error("aad");
        if (EVP_EncryptUpdate(ctx, ct.data(), &len,
                (const unsigned char*)plaintext.data(), (int)plaintext.size()) != 1) throw std::runtime_error("enc");
        int outl = len;
        if (EVP_EncryptFinal_ex(ctx, ct.data() + len, &len) != 1) throw std::runtime_error("final");
        outl += len; ct.resize(outl);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) throw std::runtime_error("tag");
    } catch (...) { EVP_CIPHER_CTX_free(ctx); throw; }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> rec; rec.reserve(8 + ct.size() + 16);
    rec.insert(rec.end(), aad, aad + 8);
    rec.insert(rec.end(), ct.begin(), ct.end());
    rec.insert(rec.end(), tag.begin(), tag.end());
    return rec;
}

// open_record: parse and check the sequence number (reject replay/reorder),
// then AEAD-decrypt and verify the tag over (seqno-as-AAD || ciphertext).
std::string open_record(const std::vector<uint8_t>& key, const std::vector<uint8_t>& record,
                        uint64_t expected_seqno) {
    if (record.size() < 8 + 16) throw std::runtime_error("record too short");
    uint64_t seq = get_seq_be(record.data());
    if (seq != expected_seqno)
        throw std::runtime_error("sequence mismatch: replay or out-of-order record");

    const EVP_CIPHER* c = cipher_for(key.size());
    std::vector<uint8_t> nonce = make_nonce(seq);
    const uint8_t* aad = record.data();                   // the 8 seqno bytes
    const uint8_t* ct = record.data() + 8;
    size_t ct_len = record.size() - 8 - 16;
    const uint8_t* tag = record.data() + record.size() - 16;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("cipher ctx");
    std::vector<uint8_t> pt(ct_len);
    int ok = 0;
    try {
        if (EVP_DecryptInit_ex(ctx, c, nullptr, nullptr, nullptr) != 1) throw std::runtime_error("init");
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1) throw std::runtime_error("ivlen");
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) throw std::runtime_error("key");
        int len = 0, outl = 0;
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad, 8) != 1) throw std::runtime_error("aad");
        if (ct_len) {
            if (EVP_DecryptUpdate(ctx, pt.data(), &len, ct, (int)ct_len) != 1) throw std::runtime_error("dec");
            outl = len;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) throw std::runtime_error("settag");
        ok = EVP_DecryptFinal_ex(ctx, pt.data() + outl, &len);
        outl += len; pt.resize(outl < 0 ? 0 : outl);
    } catch (...) { EVP_CIPHER_CTX_free(ctx); throw; }
    EVP_CIPHER_CTX_free(ctx);
    if (ok <= 0) throw std::runtime_error("authentication failed: tampered record");
    return std::string(pt.begin(), pt.end());
}

}  // namespace sl2
