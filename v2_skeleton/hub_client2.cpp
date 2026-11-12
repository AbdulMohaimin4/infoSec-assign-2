// SmartLock v2 hub (controller, client). PROVIDED scaffold: you do not need to edit this.
// It performs the secure handshake and delegates all record crypto and suite
// policy to your securelink2.cpp.
//   ./hub_client2 instance.txt [host] [port]    (port defaults to the instance port)
//
// The hub trusts the device key pinned in its own instance.txt (rsa_pub_b64),
// as if it had been established at pairing time. It aborts if the presented
// certificate does not match that pinned key, or if the signed transcript does
// not verify, so a man in the middle cannot impersonate the lock or downgrade
// the negotiation.

#include "securelink2.hpp"
#include "dh2048.hpp"
#include "pki.hpp"
#include "slink.hpp"
#include <cstdio>
#include <string>
#include <vector>
#include <sstream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using slink::Msg; using slink::Reader; using slink::send_msg;
using slink::b64enc; using slink::b64dec; using slink::to_hex; using slink::from_hex;

static std::string join(const std::vector<std::string>& v) {
    std::string s; for (size_t i = 0; i < v.size(); ++i) { if (i) s += ','; s += v[i]; }
    return s;
}
static void die(int s, const char* why) { fprintf(stderr, "[hub] abort: %s\n", why); close(s); }

int main(int argc, char** argv) {
    auto cfg = slink::read_config(argc > 1 ? argv[1] : "instance.txt");
    const char* host = argc > 2 ? argv[2] : "127.0.0.1";
    int port = std::stoi(argc > 3 ? argv[3] : cfg["port"]);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(s, (sockaddr*)&a, sizeof a) < 0) { perror("connect"); return 1; }
    Reader r(s); Msg m;

    // 1. Negotiation: offer only strong suites; refuse a NULL / unexpected pick.
    std::string offer = join(sl2::strong_suites());
    send_msg(s, {{"type","HELLO"},{"suites",offer}});
    if (!r.recv(m) || m["type"] != "SUITE") { die(s, "no suite"); return 1; }
    std::string suite = m["suite"];
    auto strong = sl2::strong_suites();
    bool ok = false; for (auto& x : strong) if (x == suite) ok = true;
    if (!ok) { die(s, "server picked a suite we do not accept"); return 1; }
    printf("[hub] negotiated suite: %s\n", suite.c_str());

    // 2. Authentication: pin the device key, verify the certificate signature.
    if (!r.recv(m) || m["type"] != "CERT") { die(s, "no cert"); return 1; }
    std::string pub_pem = b64dec(m["pubkey"]);
    if (pub_pem != b64dec(cfg["rsa_pub_b64"])) { die(s, "device key is not the pinned key"); return 1; }
    EVP_PKEY* dev = pki::load_pub(pub_pem);
    if (!pki::verify(dev, m["name"] + pub_pem, from_hex(m["sig"]))) { die(s, "bad certificate signature"); return 1; }
    printf("[hub] device authenticated: %s\n", m["name"].c_str());
    // Known limitation: PAIR still carries the v1 MD5 PIN digest. See Part B and C.2.
    send_msg(s, {{"type","PAIR"},{"hub",cfg["hub_id"]},{"pinhash",slink::md5hex(cfg["pin"])}});

    // 3. Keying: verify the signed transcript, then do our own ephemeral DH.
    if (!r.recv(m) || m["type"] != "DH") { die(s, "no DH"); return 1; }
    std::string B = m["B"];
    std::string transcript = offer + "|" + suite + "|" + B;
    if (!pki::verify(dev, transcript, from_hex(m["sig"]))) { die(s, "DH value not authenticated"); return 1; }
    EVP_PKEY_free(dev);

    std::string apriv, apub; dh2048::keygen(apriv, apub);
    send_msg(s, {{"type","DHCLIENT"},{"A",apub}});
    auto shared = dh2048::shared(B, apriv);
    auto k_c2s = sl2::derive_key(shared, suite, "c2s");   // hub to lock
    auto k_s2c = sl2::derive_key(shared, suite, "s2c");   // lock to hub

    uint64_t tx = 0, rx = 0;
    auto send_rec = [&](const std::string& t) {
        send_msg(s, {{"type","MSG"},{"rec",to_hex(sl2::seal(k_c2s, tx++, t))}});
    };
    auto recv_rec = [&]() -> std::string {
        r.recv(m); return sl2::open_record(k_s2c, from_hex(m["rec"]), rx++);
    };

    printf("[lock] %s\n", recv_rec().c_str());
    send_rec("STATUS"); printf("[lock] %s\n", recv_rec().c_str());
    send_rec("UNLOCK"); printf("[lock] %s\n", recv_rec().c_str());
    send_rec("LOCK");   printf("[lock] %s\n", recv_rec().c_str());
    send_rec("QUIT");
    close(s);
    return 0;
}
