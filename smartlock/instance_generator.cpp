// Per-student instance generator (INSTRUCTOR). Writes instance.txt for a roll.
//   ./instance_generator 22i-1234 [out.txt]
// The grading secrets (pin, flag, dh_b) are printed and are also derivable from
// the roll by grade_attack.

#include "secrets.hpp"
#include "slink.hpp"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <cstdio>
#include <fstream>

static std::string pem_of(EVP_PKEY* k, bool priv) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (priv) PEM_write_bio_PrivateKey(bio, k, nullptr, nullptr, 0, nullptr, nullptr);
    else PEM_write_bio_PUBKEY(bio, k);
    char* data; long len = BIO_get_mem_data(bio, &data);
    std::string s(data, len);
    BIO_free(bio);
    return s;
}

int main(int argc, char** argv) {
    // Parse: <roll> [out]  with an optional --secrets flag anywhere.
    // Students run `./instance_generator <roll>` and get instance.txt.
    // The instructor adds --secrets to also print the PIN and flag for grading.
    std::string roll, out = "instance.txt";
    bool show_secrets = false;
    int positional = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--secrets") { show_secrets = true; continue; }
        if (positional == 0) roll = a;
        else if (positional == 1) out = a;
        positional++;
    }
    if (roll.empty()) {
        fprintf(stderr, "usage: %s <roll> [out] [--secrets]\n", argv[0]);
        fprintf(stderr, "  e.g. %s 23i-0001\n", argv[0]);
        return 1;
    }
    secrets::Instance in = secrets::derive(roll);

    EVP_PKEY* rsa = EVP_RSA_gen(2048);
    std::string priv = slink::b64enc(pem_of(rsa, true));
    std::string pub = slink::b64enc(pem_of(rsa, false));
    EVP_PKEY_free(rsa);

    std::ofstream f(out);
    f << "roll = " << in.roll << "\n";
    f << "device_name = " << in.device_name << "\n";
    f << "device_suites = " << in.device_suites << "\n";
    f << "hub_id = " << in.hub_id << "\n";
    f << "dh_p = " << in.p << "\n";
    f << "dh_g = " << in.g << "\n";
    f << "dh_b = " << in.b << "\n";
    f << "dh_B = " << in.B << "\n";
    f << "pin = " << in.pin << "\n";
    f << "pin_md5 = " << in.pin_md5 << "\n";
    f << "static_nonce = " << in.static_nonce << "\n";
    f << "flag = " << in.flag << "\n";
    f << "port = " << in.port << "\n";
    f << "rsa_priv_b64 = " << priv << "\n";
    f << "rsa_pub_b64 = " << pub << "\n";
    f.close();

    printf("wrote %s for roll %s\n", out.c_str(), roll.c_str());
    printf("  the lock will listen on port %d\n", in.port);
    if (show_secrets) {
        printf("  dh_p           : %llu (40-bit)\n", (unsigned long long)in.p);
        printf("  pairing PIN    : %s (grading secret)\n", in.pin.c_str());
        printf("  pairing secret : %s (grading secret)\n", in.flag.c_str());
    }
    return 0;
}
