// SmartLock v2 device (lock, server). PROVIDED scaffold: you do not need to edit this.
// It wires the secure handshake and delegates all record crypto and suite
// policy to your securelink2.cpp. Build it with the Makefile in this folder.
//   ./lock_server2 instance.txt
//
// What this scaffold already does for you (the five stage fixes it relies on):
//   negotiation : offers only the strong suites that securelink2 accepts, and
//                 signs the handshake transcript so a tampered/downgraded
//                 negotiation is detected.
//   auth        : presents a signed device certificate; the hub pins the key.
//   keying      : fresh 2048-bit ephemeral DH every session (forward secrecy),
//                 and the device signs its DH value so it cannot be swapped.
//   records     : your seal()/open_record() carry a per-direction sequence
//                 number, so replay and reorder are rejected.

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
#include <unistd.h>

using slink::Msg; using slink::Reader; using slink::send_msg;
using slink::b64enc; using slink::b64dec; using slink::to_hex; using slink::from_hex;

static std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> v; std::stringstream ss(s); std::string t;
    while (std::getline(ss, t, d)) v.push_back(t);
    return v;
}

// Door state belongs to the device, not the connection: it survives across
// sessions and resets only when lock_server2 restarts.
static bool locked = true;
static int unlocks = 0;

static void handle(int c, std::map<std::string, std::string>& cfg) {
    Reader r(c); Msg m;

    // 1. Negotiation: accept only the suites securelink2 is willing to run.
    if (!r.recv(m) || m["type"] != "HELLO") return;
    std::string offered = m["suites"];
    std::string suite = sl2::choose_suite(split(offered, ','));
    if (suite.empty()) { send_msg(c, {{"type","ALERT"},{"reason","no acceptable suite"}}); return; }
    send_msg(c, {{"type","SUITE"},{"suite",suite}});

    // 2. Authentication: send the signed device certificate.
    std::string pub_pem = b64dec(cfg["rsa_pub_b64"]);
    EVP_PKEY* priv = pki::load_priv(b64dec(cfg["rsa_priv_b64"]));
    auto certsig = pki::sign(priv, cfg["device_name"] + pub_pem);
    send_msg(c, {{"type","CERT"},{"name",cfg["device_name"]},
                 {"pubkey",b64enc(pub_pem)},{"sig",to_hex(certsig)}});

    if (!r.recv(m) || m["type"] != "PAIR") { EVP_PKEY_free(priv); return; }
    if (m["pinhash"] != cfg["pin_md5"]) {
        send_msg(c, {{"type","ALERT"},{"reason","pair rejected"}}); EVP_PKEY_free(priv); return;
    }

    // 3. Keying: fresh ephemeral DH, and sign the transcript (offer|suite|B).
    std::string dpriv, dpub; dh2048::keygen(dpriv, dpub);
    std::string transcript = offered + "|" + suite + "|" + dpub;
    auto dhsig = pki::sign(priv, transcript);
    send_msg(c, {{"type","DH"},{"B",dpub},{"sig",to_hex(dhsig)}});
    EVP_PKEY_free(priv);

    if (!r.recv(m) || m["type"] != "DHCLIENT") return;
    auto shared = dh2048::shared(m["A"], dpriv);
    auto k_c2s = sl2::derive_key(shared, suite, "c2s");   // hub to lock
    auto k_s2c = sl2::derive_key(shared, suite, "s2c");   // lock to hub

    // 4 + 5. Records: per-direction sequence numbers.
    uint64_t tx = 0, rx = 0;
    auto send_rec = [&](const std::string& text) {
        send_msg(c, {{"type","MSG"},{"rec",to_hex(sl2::seal(k_s2c, tx++, text))}});
    };
    send_rec("Paired with SmartLock. Pairing secret: " + cfg["flag"]);

    while (r.recv(m)) {
        if (m["type"] != "MSG") break;
        std::string text;
        try { text = sl2::open_record(k_c2s, from_hex(m["rec"]), rx++); }
        catch (...) { break; }   // replay / reorder / tamper: drop the session
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
    auto cfg = slink::read_config(argc > 1 ? argv[1] : "instance.txt");
    int port = std::stoi(cfg["port"]);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(port);
    if (bind(s, (sockaddr*)&a, sizeof a) < 0) { perror("bind"); return 1; }
    listen(s, 5);
    printf("SmartLock v2 %s listening on port %d\n", cfg["device_name"].c_str(), port);
    fflush(stdout);
    while (true) {
        int c = accept(s, nullptr, nullptr);
        if (c < 0) continue;
        handle(c, cfg);
        close(c);
    }
}
