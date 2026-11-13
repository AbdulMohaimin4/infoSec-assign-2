// v2_attack_demo.cpp - Part C.2 evidence: the v1 record attacks fail against v2.
// Name: Abdul Mohaimin   Student ID: 23i-0652   Assignment: 2
//
// Completes a genuine v2 handshake against the live lock_server2, then tries the
// record-layer attacks that worked on v1 and shows the lock rejects each one
// (the server drops the session, so our next read returns EOF):
//   * replay   : resend an already-accepted record (wrong sequence number);
//   * reorder  : send a record with a future sequence number;
//   * tamper   : flip a byte so the AEAD tag fails.
// A baseline run shows a normal session still succeeds.
//
// Build (from v2_skeleton): g++ -std=c++17 -O2 -Wall v2_attack_demo.cpp securelink2.cpp -o v2_attack_demo -lcrypto
// Run:   ./v2_attack_demo <instance.txt> <host> <port> <baseline|replay|reorder|tamper>

#include "securelink2.hpp"
#include "dh2048.hpp"
#include "pki.hpp"
#include "slink.hpp"
#include <cstdio>
#include <string>
#include <vector>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using slink::Msg; using slink::Reader; using slink::send_msg;
using slink::b64dec; using slink::to_hex; using slink::from_hex;

struct Link { int s; Reader* r; std::vector<uint8_t> k_c2s, k_s2c; };

// A faithful v2 hub handshake; leaves the link ready and the greeting consumed.
static bool handshake(std::map<std::string,std::string>& cfg, const char* host, int port, Link& out) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(s, (sockaddr*)&a, sizeof a) < 0) { perror("connect"); return false; }
    Reader* r = new Reader(s); Msg m;

    std::string offer = "AES256-GCM,AES128-GCM";
    send_msg(s, {{"type","HELLO"},{"suites",offer}});
    if (!r->recv(m) || m["type"] != "SUITE") return false;
    std::string suite = m["suite"];
    if (!r->recv(m) || m["type"] != "CERT") return false;
    std::string pub_pem = b64dec(m["pubkey"]);
    EVP_PKEY* dev = pki::load_pub(pub_pem);
    send_msg(s, {{"type","PAIR"},{"hub",cfg["hub_id"]},{"pinhash",slink::md5hex(cfg["pin"])}});
    if (!r->recv(m) || m["type"] != "DH") return false;
    std::string B = m["B"];
    if (!pki::verify(dev, offer + "|" + suite + "|" + B, from_hex(m["sig"]))) return false;
    EVP_PKEY_free(dev);
    std::string apriv, apub; dh2048::keygen(apriv, apub);
    send_msg(s, {{"type","DHCLIENT"},{"A",apub}});
    auto shared = dh2048::shared(B, apriv);
    out.s = s; out.r = r;
    out.k_c2s = sl2::derive_key(shared, suite, "c2s");
    out.k_s2c = sl2::derive_key(shared, suite, "s2c");
    // consume the greeting (lock tx seq 0)
    if (!r->recv(m) || m["type"] != "MSG") return false;
    std::string greet = sl2::open_record(out.k_s2c, from_hex(m["rec"]), 0);
    std::printf("    handshake ok; greeting: %s\n", greet.c_str());
    return true;
}

static void send_rec(Link& L, const std::vector<uint8_t>& rec) {
    send_msg(L.s, {{"type","MSG"},{"rec",to_hex(rec)}});
}
// Try to read a reply; return false if the lock dropped the session (EOF).
static bool try_reply(Link& L, uint64_t expect_seq, std::string& out) {
    Msg m;
    if (!L.r->recv(m) || m["type"] != "MSG") return false;
    try { out = sl2::open_record(L.k_s2c, from_hex(m["rec"]), expect_seq); }
    catch (...) { return false; }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 5) { std::fprintf(stderr, "usage: %s <instance> <host> <port> <mode>\n", argv[0]); return 2; }
    auto cfg = slink::read_config(argv[1]);
    const char* host = argv[2]; int port = atoi(argv[3]); std::string mode = argv[4];

    Link L;
    if (!handshake(cfg, host, port, L)) { std::printf("[%s] handshake failed\n", mode.c_str()); return 1; }

    std::string reply;
    if (mode == "baseline") {
        send_rec(L, sl2::seal(L.k_c2s, 0, "STATUS"));
        if (try_reply(L, 1, reply)) std::printf("[baseline] PASS - normal record accepted: %s\n", reply.c_str());
        else std::printf("[baseline] unexpected drop\n");
    } else if (mode == "replay") {
        auto rec0 = sl2::seal(L.k_c2s, 0, "STATUS");
        send_rec(L, rec0); try_reply(L, 1, reply);
        std::printf("    first STATUS accepted: %s\n", reply.c_str());
        send_rec(L, rec0);                                  // resend seq 0 (lock now expects seq 1)
        bool got = try_reply(L, 2, reply);
        std::printf("[replay] %s - replayed record %s\n", got ? "FAIL" : "PASS",
                    got ? "was accepted" : "rejected (lock dropped the session)");
    } else if (mode == "reorder") {
        send_rec(L, sl2::seal(L.k_c2s, 1, "STATUS"));        // skip seq 0
        bool got = try_reply(L, 1, reply);
        std::printf("[reorder] %s - out-of-order record %s\n", got ? "FAIL" : "PASS",
                    got ? "was accepted" : "rejected (lock dropped the session)");
    } else if (mode == "tamper") {
        auto rec = sl2::seal(L.k_c2s, 0, "STATUS");
        rec[rec.size() - 1] ^= 0x01;                         // flip a tag bit
        send_rec(L, rec);
        bool got = try_reply(L, 1, reply);
        std::printf("[tamper] %s - tampered record %s\n", got ? "FAIL" : "PASS",
                    got ? "was accepted" : "rejected (lock dropped the session)");
    } else { std::fprintf(stderr, "unknown mode\n"); return 2; }

    close(L.s);
    return 0;
}
