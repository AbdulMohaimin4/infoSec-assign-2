SmartLock Assignment 2 - README
Name: Abdul Mohaimin   Roll: 23i-0652   Section: G

Toolchain: C++17, g++ (tested g++ 13.3), OpenSSL libcrypto (OpenSSL 3.x).
  sudo apt install build-essential libssl-dev

====================================================================
0. GENERATE THE INSTANCE (once)
====================================================================
  cd smartlock
  make
  ./instance_generator 23i-0652      # writes instance.txt (lock config + flag)
  # lock listens on the port printed (this instance: 9085)

Run v1 lock + a normal hub (two terminals / two VMs):
  ./lock_server instance.txt
  ./hub_client  instance.txt <host> [port]

====================================================================
1. PART A EXPLOITS   (folder: exploits/)
====================================================================
Shared code:
  23i-0652-G-TASKA-wire.hpp   reads a capture (.pcap OR a reassembled text
                              stream) and parses the line protocol; provides the
                              discrete-log, key-recovery, and AES-GCM helpers.
Build any exploit:
  g++ -std=c++17 -O2 -Wall exploits/<file>.cpp -o <name> -lcrypto

How the capture is produced:
  * In the lab: tcpdump -i <host-only-iface> -w session.pcap tcp port 9085
    (then feed session.pcap directly to any tool below), OR
  * use the relay's --dump to record the reassembled stream as text.

TASKA1 - Downgrade (negotiation). On-path relay; rewrites HELLO -> NULL.
  ./taska1 --listen 8000 --to <lock_host>:9085 --downgrade --show-flag
  # point the hub at the relay:  ./hub_client instance.txt <relay_host> 8000
  # also runs passively (just --dump FILE) to capture a session for the others.

TASKA2 - Impersonation / MITM (authentication). Active man-in-the-middle.
  ./taska2 --listen 8000 --to <lock_host>:9085 [--tamper]
  # hub -> relay; reads the flag + every record in clear; --tamper: LOCK->UNLOCK.
  PIN recovery (second Stage-2 weakness):
  ./pincrack <capture> smartlock/pin_wordlist.txt
  # or:  hashcat -m 0 -a 6 pin.hash smartlock/pin_wordlist.txt ?d?d?d

TASKA3 - Keying recovery (discrete log -> key -> flag).
  ./taska3 <capture.pcap|stream.txt>

TASKA4 - Nonce reuse (two-time pad; emits nonce_xor_hex).
  ./taska4 <capture.pcap|stream.txt>

TASKA5 - Replay (teardown). Replays the captured UNLOCK to the live lock.
  ./taska5 <capture.pcap|stream.txt> <lock_host> 9085
  # run twice: the unlock counter climbs.

answers.txt (repo root) holds the recovered A.1 values.

====================================================================
2. PART C: v2 SECURITY CORE   (folder: v2_skeleton/)
====================================================================
  cd v2_skeleton && make           # builds lock_server2 + hub_client2
  ./lock_server2 ../smartlock/instance.txt
  ./hub_client2  ../smartlock/instance.txt 127.0.0.1

  Self-test (the six C.1 checks):
  g++ -std=c++17 -O2 -Wall securelink2_selftest.cpp securelink2.cpp -o selftest -lcrypto
  ./selftest

  C.2 record attacks vs v2:
  g++ -std=c++17 -O2 -Wall v2_attack_demo.cpp securelink2.cpp -o v2_attack_demo -lcrypto
  ./v2_attack_demo ../smartlock/instance.txt 127.0.0.1 9085 <baseline|replay|reorder|tamper>
  # downgrade vs v2:   ../exploits/taska1 --listen 8000 --to 127.0.0.1:9085 --downgrade
  # MITM/DH-swap vs v2: ../exploits/taska1 --listen 8000 --to 127.0.0.1:9085 --corrupt-dh

====================================================================
3. PART D: PERFORMANCE   (folder: performance/)
====================================================================
  g++ -std=c++17 -O2 -Wall performance/23i-0652-G-TASKD-V1.cpp v2_skeleton/securelink2.cpp -Ismartlock -Iv2_skeleton -o taskd -lcrypto
  ./taskd records
  # with a lock running on 9085:
  ./taskd handshake v1 127.0.0.1 9085 30 smartlock/instance.txt   # v1 lock running
  ./taskd handshake v2 127.0.0.1 9085 30 smartlock/instance.txt   # v2 lock running
  python3 performance/plot.py        # -> performance/chart.png

Scope and ethics: all capture/interception was done only inside an isolated,
host-only VM lab between my own machines. Nothing was run against any third-party
system.
