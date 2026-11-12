// SmartLock v2 record and policy module (STUDENT SKELETON).
// Implement every function marked TODO, keeping the signatures in securelink2.hpp.
// You may add private helpers. Build and self-check with the grader:
//     make && ../grader/grade_v2   (after copying your file where the grader expects)
//
// Suggested OpenSSL building blocks: EVP for AES-GCM, EVP_KDF "HKDF" for the key.

#include "securelink2.hpp"
#include <stdexcept>

namespace sl2 {

std::vector<std::string> strong_suites() {
    // TODO: return the suites you accept. Must not include "NULL".
    throw std::runtime_error("TODO strong_suites");
}

std::string choose_suite(const std::vector<std::string>& hub_offer) {
    // TODO: pick the strongest common suite; return "" to abort; never "NULL".
    (void)hub_offer;
    throw std::runtime_error("TODO choose_suite");
}

std::vector<uint8_t> derive_key(const std::vector<uint8_t>& shared_secret,
                                const std::string& suite, const std::string& context) {
    // TODO: derive the record key with a KDF (e.g. HKDF-SHA256). Not the raw secret.
    (void)shared_secret; (void)suite; (void)context;
    throw std::runtime_error("TODO derive_key");
}

std::vector<uint8_t> make_nonce(uint64_t seqno) {
    // TODO: a 12-byte nonce, unique per sequence number.
    (void)seqno;
    throw std::runtime_error("TODO make_nonce");
}

std::vector<uint8_t> seal(const std::vector<uint8_t>& key, uint64_t seqno, const std::string& plaintext) {
    // TODO: AEAD encrypt, binding the sequence number.
    (void)key; (void)seqno; (void)plaintext;
    throw std::runtime_error("TODO seal");
}

std::string open_record(const std::vector<uint8_t>& key, const std::vector<uint8_t>& record,
                        uint64_t expected_seqno) {
    // TODO: parse the sequence number, reject if not expected, then AEAD decrypt.
    (void)key; (void)record; (void)expected_seqno;
    throw std::runtime_error("TODO open_record");
}

}  // namespace sl2
