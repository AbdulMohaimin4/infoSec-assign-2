// Strong ephemeral Diffie-Hellman over the RFC 3526 2048-bit MODP group.
// Provided for the v2 scaffold (students do not edit this). OpenSSL BIGNUM.
#ifndef DH2048_HPP
#define DH2048_HPP
#include <openssl/bn.h>
#include <string>
#include <vector>
#include <cstdint>

namespace dh2048 {

inline BIGNUM* P() {
    BIGNUM* p = nullptr;
    BN_hex2bn(&p,
      "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
      "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
      "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
      "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
      "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
      "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
      "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
      "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF");
    return p;
}

inline void keygen(std::string& priv_hex, std::string& pub_hex) {
    BIGNUM* p = P(); BN_CTX* c = BN_CTX_new();
    BIGNUM* g = BN_new(); BN_set_word(g, 2);
    BIGNUM* a = BN_new(); BN_rand(a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    BIGNUM* A = BN_new(); BN_mod_exp(A, g, a, p, c);
    char* ah = BN_bn2hex(a); char* Ah = BN_bn2hex(A);
    priv_hex = ah; pub_hex = Ah;
    OPENSSL_free(ah); OPENSSL_free(Ah);
    BN_free(a); BN_free(A); BN_free(g); BN_free(p); BN_CTX_free(c);
}

inline std::vector<uint8_t> shared(const std::string& peer_pub_hex, const std::string& priv_hex) {
    BIGNUM* p = P(); BN_CTX* c = BN_CTX_new();
    BIGNUM* B = nullptr; BN_hex2bn(&B, peer_pub_hex.c_str());
    BIGNUM* a = nullptr; BN_hex2bn(&a, priv_hex.c_str());
    BIGNUM* s = BN_new(); BN_mod_exp(s, B, a, p, c);
    std::vector<uint8_t> out(256); BN_bn2binpad(s, out.data(), 256);
    BN_free(B); BN_free(a); BN_free(s); BN_free(p); BN_CTX_free(c);
    return out;
}

}  // namespace dh2048
#endif
