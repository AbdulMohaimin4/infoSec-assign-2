// RSA load / sign / verify helpers (OpenSSL). Shared by the lock (v1) and v2.
#ifndef PKI_HPP
#define PKI_HPP
#include <string>
#include <vector>
#include <cstdint>
#include <openssl/pem.h>
#include <openssl/evp.h>

namespace pki {

inline EVP_PKEY* load_priv(const std::string& pem) {
    BIO* b = BIO_new_mem_buf(pem.data(), (int)pem.size());
    EVP_PKEY* k = PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr);
    BIO_free(b); return k;
}
inline EVP_PKEY* load_pub(const std::string& pem) {
    BIO* b = BIO_new_mem_buf(pem.data(), (int)pem.size());
    EVP_PKEY* k = PEM_read_bio_PUBKEY(b, nullptr, nullptr, nullptr);
    BIO_free(b); return k;
}
inline std::vector<uint8_t> sign(EVP_PKEY* k, const std::string& msg) {
    EVP_MD_CTX* c = EVP_MD_CTX_new(); size_t len = 0;
    EVP_DigestSignInit(c, nullptr, EVP_sha256(), nullptr, k);
    EVP_DigestSign(c, nullptr, &len, (const unsigned char*)msg.data(), msg.size());
    std::vector<uint8_t> sig(len);
    EVP_DigestSign(c, sig.data(), &len, (const unsigned char*)msg.data(), msg.size());
    sig.resize(len); EVP_MD_CTX_free(c); return sig;
}
inline bool verify(EVP_PKEY* k, const std::string& msg, const std::vector<uint8_t>& sig) {
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(c, nullptr, EVP_sha256(), nullptr, k);
    int ok = EVP_DigestVerify(c, sig.data(), sig.size(), (const unsigned char*)msg.data(), msg.size());
    EVP_MD_CTX_free(c); return ok == 1;
}

}  // namespace pki
#endif
