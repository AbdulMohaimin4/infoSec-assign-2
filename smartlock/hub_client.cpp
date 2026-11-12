// SmartLock v1 hub (controller, client). C++ / OpenSSL.
//   ./hub_client instance.txt [host] [port]     (port defaults to the instance port)
#include "slink.hpp"
#include <cstdio>
#include <string>
#include <random>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace slink;

int main(int argc, char** argv) {
    auto cfg = read_config(argc > 1 ? argv[1] : "instance.txt");
    const char* host = argc > 2 ? argv[2] : "127.0.0.1";
    int port = std::stoi(argc > 3 ? argv[3] : cfg["port"]);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(s, (sockaddr*)&a, sizeof a) < 0) { perror("connect"); return 1; }
    Reader r(s); Msg m;

    send_msg(s, {{"type","HELLO"},{"suites","AES256-GCM,AES128-GCM,NULL"}});
    r.recv(m); std::string suite = m["suite"];
    printf("[hub] negotiated suite: %s\n", suite.c_str());

    r.recv(m);  // CERT, not validated
    printf("[hub] device claims to be: %s (certificate not checked)\n", m["name"].c_str());
    send_msg(s, {{"type","PAIR"},{"hub",cfg["hub_id"]},{"pinhash",md5hex(cfg["pin"])}});

    r.recv(m);
    uint64_t p = std::stoull(m["p"]), g = std::stoull(m["g"]), B = std::stoull(m["B"]);
    std::mt19937_64 rng(std::random_device{}());
    uint64_t av = 2 + rng() % (p - 3);
    send_msg(s, {{"type","DHCLIENT"},{"A", std::to_string(modexp(g, av, p))}});
    auto key = session_key(modexp(B, av, p), suite);
    auto nonce = from_hex(cfg["static_nonce"]);

    auto send = [&](const std::string& t) {
        auto ct = record_encrypt(suite, key, nonce, t);
        send_msg(s, {{"type","MSG"},{"nonce",cfg["static_nonce"]},{"ct",to_hex(ct)}});
    };
    auto recv = [&]() -> std::string {
        r.recv(m);
        return record_decrypt(suite, key, from_hex(m["nonce"]), from_hex(m["ct"]));
    };

    printf("[lock] %s\n", recv().c_str());
    send("STATUS"); printf("[lock] %s\n", recv().c_str());
    send("UNLOCK"); printf("[lock] %s\n", recv().c_str());
    send("LOCK");   printf("[lock] %s\n", recv().c_str());
    send("QUIT");
    close(s);
    return 0;
}
