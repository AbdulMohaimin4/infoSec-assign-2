// 23i-0652-G-TASKD-V1.cpp - Part D performance study: v1 vs v2.
// Name: Abdul Mohaimin   Student ID: 23i-0652   Section: G   Assignment: 2
//
// Measures, for both versions on the same machine with the same flags:
//   * per-record overhead   : extra wire bytes vs plaintext, and the time to
//                             seal and to open one record;
//   * throughput            : MB/s sealing and opening 1 KiB records;
//   * handshake time        : TCP connect -> greeting decrypted (networked).
//
// v1 record crypto = raw-secret AES-256-GCM, static nonce (slink.hpp).
// v2 record crypto = HKDF key, per-record nonce, sequence-bound AEAD (securelink2).
//
// Build (from repo root), all on one line:
//   g++ -std=c++17 -O2 -Wall performance/23i-0652-G-TASKD-V1.cpp v2_skeleton/securelink2.cpp -Ismartlock -Iv2_skeleton -o taskd -lcrypto
// Run:
//   ./taskd records
//   ./taskd handshake v1 127.0.0.1 9085 30 smartlock/instance.txt    # lock_server running
//   ./taskd handshake v2 127.0.0.1 9085 30 smartlock/instance.txt    # lock_server2 running

#include "slink.hpp"            // v1 framing + raw-secret record crypto
#include "securelink2.hpp"      // v2 record crypto / policy
#include "dh2048.hpp"           // v2 ephemeral DH
#include "pki.hpp"              // v2 RSA verify
#include <cstdio>
#include <cmath>
#include <chrono>
#include <string>
#include <vector>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using clk = std::chrono::steady_clock;
static double us_since(clk::time_point t0) {
    return std::chrono::duration<double, std::micro>(clk::now() - t0).count();
}
struct Stat { double mean, sd; };
static Stat stats(const std::vector<double>& v) {
    double m = 0; for (double x : v) m += x; m /= v.size();
    double s = 0; for (double x : v) s += (x - m) * (x - m);
    s = v.size() > 1 ? std::sqrt(s / (v.size() - 1)) : 0;
    return { m, s };
}

// ---- record micro-benchmarks (in process) --------------------------------
static void bench_records() {
    using namespace slink;
    const std::string suite = "AES256-GCM";
    std::vector<uint8_t> key(32, 0x2b);
    std::vector<uint8_t> nonce = from_hex("086421c21b34a824e019d43d");  // v1 static nonce

    std::printf("== Per-record overhead (bytes on the wire) ==\n");
    std::printf("  %-10s %10s %12s %12s %10s\n", "version", "plaintext", "crypto+hdr", "wire line", "overhead");
    for (size_t pt_len : { (size_t)6, (size_t)1024 }) {
        std::string pt(pt_len, 'A');
        // v1: fields ct(hex of pt+16 tag) + nonce(hex 12B) + type:MSG
        auto v1ct = record_encrypt(suite, key, nonce, pt);
        Msg v1m = {{"ct", to_hex(v1ct)}, {"nonce", to_hex(nonce)}, {"type", "MSG"}};
        std::string v1line; { bool f = true; for (auto& kv : v1m) { if (!f) v1line += '\t'; f = false; v1line += kv.first + ":" + kv.second; } v1line += '\n'; }
        // v2: field rec(hex of seq8+pt+tag16) + type:MSG
        auto v2rec = sl2::seal(key, 0, pt);
        Msg v2m = {{"rec", to_hex(v2rec)}, {"type", "MSG"}};
        std::string v2line; { bool f = true; for (auto& kv : v2m) { if (!f) v2line += '\t'; f = false; v2line += kv.first + ":" + kv.second; } v2line += '\n'; }
        std::printf("  %-10s %10zu %12zu %12zu %+10lld\n", "v1", pt_len, v1ct.size(), v1line.size(), (long long)(v1line.size() - pt_len));
        std::printf("  %-10s %10zu %12zu %12zu %+10lld\n", "v2", pt_len, v2rec.size(), v2line.size(), (long long)(v2line.size() - pt_len));
    }

    std::printf("\n== Single-record latency (mean +/- sd over 20000 ops, 1 KiB) ==\n");
    std::string pt(1024, 'A');
    const int N = 20000;
    { std::vector<double> t; t.reserve(N);
      for (int i = 0; i < N; ++i) { auto t0 = clk::now(); volatile auto r = record_encrypt(suite, key, nonce, pt); (void)r; t.push_back(us_since(t0)); }
      auto s = stats(t); std::printf("  v1 seal: %.3f +/- %.3f us\n", s.mean, s.sd); }
    { auto rec = record_encrypt(suite, key, nonce, pt); std::vector<double> t; t.reserve(N);
      for (int i = 0; i < N; ++i) { auto t0 = clk::now(); volatile auto r = record_decrypt(suite, key, nonce, rec); (void)r; t.push_back(us_since(t0)); }
      auto s = stats(t); std::printf("  v1 open: %.3f +/- %.3f us\n", s.mean, s.sd); }
    { std::vector<double> t; t.reserve(N);
      for (int i = 0; i < N; ++i) { auto t0 = clk::now(); volatile auto r = sl2::seal(key, i, pt); (void)r; t.push_back(us_since(t0)); }
      auto s = stats(t); std::printf("  v2 seal: %.3f +/- %.3f us\n", s.mean, s.sd); }
    { auto rec = sl2::seal(key, 0, pt); std::vector<double> t; t.reserve(N);
      for (int i = 0; i < N; ++i) { auto t0 = clk::now(); volatile auto r = sl2::open_record(key, rec, 0); (void)r; t.push_back(us_since(t0)); }
      auto s = stats(t); std::printf("  v2 open: %.3f +/- %.3f us\n", s.mean, s.sd); }

    std::printf("\n== Throughput (1 KiB records, 10000/run, 5 runs; MB/s) ==\n");
    FILE* csv = fopen("performance/throughput.csv", "w");
    if (csv) fprintf(csv, "version,op,run,mb_per_s\n");
    const int RECS = 10000, RUNS = 5;
    double bytes_per_run = (double)RECS * 1024.0;
    auto run_tp = [&](const char* ver, const char* op, auto fn) {
        std::vector<double> mbs;
        for (int run = 0; run < RUNS; ++run) {
            auto t0 = clk::now();
            for (int i = 0; i < RECS; ++i) fn(i);
            double sec = us_since(t0) / 1e6;
            double mb = (bytes_per_run / (1024.0 * 1024.0)) / sec;
            mbs.push_back(mb);
            if (csv) fprintf(csv, "%s,%s,%d,%.2f\n", ver, op, run, mb);
        }
        auto s = stats(mbs);
        std::printf("  %-3s %-5s %8.1f +/- %5.1f MB/s\n", ver, op, s.mean, s.sd);
    };
    run_tp("v1", "seal", [&](int){ volatile auto r = record_encrypt(suite, key, nonce, pt); (void)r; });
    { auto rec = record_encrypt(suite, key, nonce, pt);
      run_tp("v1", "open", [&](int){ volatile auto r = record_decrypt(suite, key, nonce, rec); (void)r; }); }
    run_tp("v2", "seal", [&](int i){ volatile auto r = sl2::seal(key, i, pt); (void)r; });
    { auto rec = sl2::seal(key, 0, pt);
      run_tp("v2", "open", [&](int){ volatile auto r = sl2::open_record(key, rec, 0); (void)r; }); }
    if (csv) fclose(csv);
    std::printf("  (raw data -> performance/throughput.csv)\n");
}

// ---- networked handshake timing ------------------------------------------
static int connect_to(const char* host, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(s, (sockaddr*)&a, sizeof a) < 0) { perror("connect"); return -1; }
    return s;
}
// One v1 handshake; returns connect->greeting-decrypted microseconds, or -1.
static double handshake_v1(const char* host, int port, std::map<std::string,std::string>& cfg) {
    using namespace slink;
    auto t0 = clk::now();
    int s = connect_to(host, port); if (s < 0) return -1;
    Reader r(s); Msg m;
    send_msg(s, {{"type","HELLO"},{"suites","AES256-GCM,AES128-GCM,NULL"}});
    r.recv(m); std::string suite = m["suite"];
    r.recv(m);                                     // CERT
    send_msg(s, {{"type","PAIR"},{"hub",cfg["hub_id"]},{"pinhash",md5hex(cfg["pin"])}});
    r.recv(m);                                     // DH p,g,B
    uint64_t p = std::strtoull(m["p"].c_str(),0,10), g = std::strtoull(m["g"].c_str(),0,10), B = std::strtoull(m["B"].c_str(),0,10);
    uint64_t a = 123456789ULL % (p ? p : 1);
    send_msg(s, {{"type","DHCLIENT"},{"A",std::to_string(modexp(g,a,p))}});
    auto key = session_key(modexp(B,a,p), suite);
    r.recv(m);                                     // greeting
    volatile auto pt = record_decrypt(suite, key, from_hex(m["nonce"]), from_hex(m["ct"]));
    (void)pt;
    double us = us_since(t0); close(s); return us;
}
// One v2 handshake (full auth: pin cert, verify signed DH).
static double handshake_v2(const char* host, int port, std::map<std::string,std::string>& cfg) {
    using namespace slink;
    auto t0 = clk::now();
    int s = connect_to(host, port); if (s < 0) return -1;
    Reader r(s); Msg m;
    std::string offer = "AES256-GCM,AES128-GCM";
    send_msg(s, {{"type","HELLO"},{"suites",offer}});
    r.recv(m); std::string suite = m["suite"];
    r.recv(m);                                     // CERT
    std::string pub_pem = b64dec(m["pubkey"]);
    EVP_PKEY* dev = pki::load_pub(pub_pem);
    pki::verify(dev, m["name"] + pub_pem, from_hex(m["sig"]));
    send_msg(s, {{"type","PAIR"},{"hub",cfg["hub_id"]},{"pinhash",md5hex(cfg["pin"])}});
    r.recv(m);                                     // DH B + sig
    std::string B = m["B"];
    pki::verify(dev, offer + "|" + suite + "|" + B, from_hex(m["sig"]));
    EVP_PKEY_free(dev);
    std::string apriv, apub; dh2048::keygen(apriv, apub);
    send_msg(s, {{"type","DHCLIENT"},{"A",apub}});
    auto shared = dh2048::shared(B, apriv);
    auto k_s2c = sl2::derive_key(shared, suite, "s2c");
    r.recv(m);                                     // greeting
    volatile auto pt = sl2::open_record(k_s2c, from_hex(m["rec"]), 0);
    (void)pt;
    double us = us_since(t0); close(s); return us;
}

static void bench_handshake(const std::string& ver, const char* host, int port, int runs, const char* inst) {
    auto cfg = slink::read_config(inst);
    std::vector<double> t; t.reserve(runs);
    for (int i = 0; i < runs; ++i) {
        double us = (ver == "v1") ? handshake_v1(host, port, cfg) : handshake_v2(host, port, cfg);
        if (us < 0) { std::fprintf(stderr, "handshake failed on run %d\n", i); return; }
        t.push_back(us);
    }
    auto s = stats(t);
    std::printf("%s handshake over %d runs: %.1f +/- %.1f us (%.3f ms mean)\n",
                ver.c_str(), runs, s.mean, s.sd, s.mean / 1000.0);
    FILE* csv = fopen("performance/handshake.csv", "a");
    if (csv) { for (size_t i = 0; i < t.size(); ++i) fprintf(csv, "%s,%zu,%.1f\n", ver.c_str(), i, t[i]); fclose(csv); }
}

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "records") { bench_records(); return 0; }
    if (argc >= 7 && std::string(argv[1]) == "handshake") {
        bench_handshake(argv[2], argv[3], atoi(argv[4]), atoi(argv[5]), argv[6]); return 0;
    }
    std::fprintf(stderr, "usage:\n  %s records\n  %s handshake <v1|v2> <host> <port> <runs> <instance>\n", argv[0], argv[0]);
    return 2;
}
