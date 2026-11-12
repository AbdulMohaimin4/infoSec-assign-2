// SmartLock v1 device (lock, server). Deliberately weak. C++ / OpenSSL.
//   ./lock_server instance.txt
#include "slink.hpp"
#include "pki.hpp"
#include <cstdio>
#include <string>
#include <vector>
#include <sstream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace slink;

static std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> v; std::stringstream ss(s); std::string t;
    while (std::getline(ss, t, d)) v.push_back(t);
    return v;
}

static std::string pick_suite(const std::vector<std::string>& hub, const std::vector<std::string>& dev) {
    std::string best; int bs = -1;
    for (auto& s : hub) {
        bool ok = false; for (auto& d : dev) if (d == s) ok = true;
        if (ok && suite_strength(s) > bs) { bs = suite_strength(s); best = s; }
    }
    return best;
}

// Door state belongs to the device, not the connection: it survives across
// sessions and resets only when lock_server restarts.
static bool locked = true;
static int unlocks = 0;

static void handle(int c, std::map<std::string, std::string>& cfg) {
    Reader r(c);
    std::string suite;
    uint64_t p = std::stoull(cfg["dh_p"]), g = std::stoull(cfg["dh_g"]), B = std::stoull(cfg["dh_B"]);
    uint64_t b = std::stoull(cfg["dh_b"]);
    auto dev = split(cfg["device_suites"], ',');

    Msg m;
    if (!r.recv(m) || m["type"] != "HELLO") return;
    suite = pick_suite(split(m["suites"], ','), dev);
    if (suite.empty()) { send_msg(c, {{"type","ALERT"},{"reason","no suite"}}); return; }
    send_msg(c, {{"type","SUITE"},{"suite",suite}});

    // self-signed device certificate (the hub never validates it)
    std::string pub_pem = b64dec(cfg["rsa_pub_b64"]);
    EVP_PKEY* priv = pki::load_priv(b64dec(cfg["rsa_priv_b64"]));
    auto sig = pki::sign(priv, cfg["device_name"] + pub_pem);
    send_msg(c, {{"type","CERT"},{"name",cfg["device_name"]},
                 {"pubkey", b64enc(pub_pem)},{"sig", to_hex(sig)}});
    EVP_PKEY_free(priv);

    if (!r.recv(m) || m["type"] != "PAIR") return;
    if (m["pinhash"] != cfg["pin_md5"]) { send_msg(c, {{"type","ALERT"},{"reason","pair rejected"}}); return; }

    send_msg(c, {{"type","DH"},{"p",std::to_string(p)},{"g",std::to_string(g)},{"B",std::to_string(B)}});
    if (!r.recv(m) || m["type"] != "DHCLIENT") return;
    uint64_t A = std::stoull(m["A"]);
    auto key = session_key(modexp(A, b, p), suite);
    auto nonce = from_hex(cfg["static_nonce"]);

    auto send_rec = [&](const std::string& text) {
        auto ct = record_encrypt(suite, key, nonce, text);
        send_msg(c, {{"type","MSG"},{"nonce",cfg["static_nonce"]},{"ct",to_hex(ct)}});
    };
    send_rec("Paired with SmartLock. Pairing secret: " + cfg["flag"]);

    while (r.recv(m)) {
        if (m["type"] != "MSG") break;
        std::string text;
        try { text = record_decrypt(suite, key, from_hex(m["nonce"]), from_hex(m["ct"])); }
        catch (...) { send_rec("ERROR bad record"); continue; }
        std::stringstream ss(text); std::string cmd; ss >> cmd;
        for (auto& ch : cmd) ch = toupper(ch);
        if (cmd == "STATUS") send_rec("STATE " + std::string(locked ? "LOCKED" : "UNLOCKED") + " unlocks=" + std::to_string(unlocks));
        else if (cmd == "UNLOCK") { locked = false; unlocks++; send_rec("DOOR OPENED (unlock #" + std::to_string(unlocks) + ")"); }
        else if (cmd == "LOCK") { locked = true; send_rec("DOOR LOCKED"); }
        else if (cmd == "QUIT") break;
        else send_rec("ERROR unknown command");
    }
}

int main(int argc, char** argv) {
    auto cfg = read_config(argc > 1 ? argv[1] : "instance.txt");
    int port = std::stoi(cfg["port"]);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(port);
    if (bind(s, (sockaddr*)&a, sizeof a) < 0) { perror("bind"); return 1; }
    listen(s, 5);
    printf("SmartLock %s listening on port %d\n", cfg["device_name"].c_str(), port);
    fflush(stdout);
    while (true) {
        int c = accept(s, nullptr, nullptr);
        if (c < 0) continue;
        handle(c, cfg);
        close(c);
    }
}
