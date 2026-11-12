// SmartLock v2 record and policy interface (C++). The grader links against your
// securelink2.cpp and calls these functions, so keep every signature below.
//
// Contracts (all graded):
//   strong_suites()  : the suites you accept; must NOT contain "NULL".
//   choose_suite()   : pick the strongest common suite; return "" to abort;
//                      never return "NULL".
//   derive_key()     : derive the record key from the DH secret with a KDF
//                      (e.g. HKDF-SHA256); must NOT return the raw secret.
//   make_nonce()     : a 12-byte nonce, unique per sequence number under a key.
//   seal()/open()    : AEAD that binds the sequence number; open_record must
//                      throw if the record's sequence number is not the one
//                      expected (this rejects replays / out-of-order records).
#ifndef SECURELINK2_HPP
#define SECURELINK2_HPP

#include <string>
#include <vector>
#include <cstdint>

namespace sl2 {

inline int keylen(const std::string& suite) {
    if (suite == "AES256-GCM") return 32;
    if (suite == "AES128-GCM") return 16;
    return 0;
}

std::vector<std::string> strong_suites();
std::string choose_suite(const std::vector<std::string>& hub_offer);
std::vector<uint8_t> derive_key(const std::vector<uint8_t>& shared_secret,
                                const std::string& suite, const std::string& context);
std::vector<uint8_t> make_nonce(uint64_t seqno);
std::vector<uint8_t> seal(const std::vector<uint8_t>& key, uint64_t seqno, const std::string& plaintext);
std::string open_record(const std::vector<uint8_t>& key, const std::vector<uint8_t>& record,
                        uint64_t expected_seqno);

}  // namespace sl2
#endif
