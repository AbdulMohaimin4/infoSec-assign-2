# SmartLock Security Assignment Report

**Name:** Abdul Mohaimin  **Roll:** 23i-0652  **Section:** G  **Assignment:** 2

**Build commands (all C++17, g++ + OpenSSL `libcrypto`):**

```
# v1 + instance
make -C smartlock && (cd smartlock && ./instance_generator 23i-0652)
# Part A exploits (each, from exploits/)
g++ -std=c++17 -O2 -Wall exploits/<FILE>.cpp -o <name> -lcrypto
# Part C v2
make -C v2_skeleton
# Part D
g++ -std=c++17 -O2 -Wall performance/23i-0652-G-TASKD-V1.cpp v2_skeleton/securelink2.cpp -Ismartlock -Iv2_skeleton -o taskd -lcrypto
```

---

## 1. Scope and ethics

All capture, interception, relaying, and replay described here were performed only
inside an isolated, host-only VMware lab between my own virtual machines (a Kali
attacker/hub VM and a separate lock VM on a host-only network with no NAT and no
bridge to the campus network or the internet). No technique was ever directed at
any system I do not own or am not authorised to test. The pairing secret, PIN, and
keys shown are from my own generated instance (`./instance_generator 23i-0652`).

---

## 2. Part A: Breaking SmartLock v1

**Lab model.** Lock on its own VM; Kali runs the hub and an on-path **local relay**
(the two-VM layout). A normal session is captured with
`tcpdump -i <host-only-iface> -w session.pcap tcp port 9085`. Every Part A tool
reads values **from the capture** (a `.pcap`, or a reassembled text stream), never
from `instance.txt`; the shared reader is `exploits/23i-0652-G-TASKA-wire.hpp`.

The captures were taken on the host-only lab link (`eth1`, `192.168.93.0/24`) between
the Kali attacker VM (`.128`) and the lock VM (`.129`). A normal session in Wireshark's
Follow TCP Stream shows the whole handshake in clear:

![Normal session (Follow TCP Stream): HELLO/SUITE/CERT/PAIR/DH/DHCLIENT/MSG in clear](evidence/baseline_stream.png)

**Recovered A.1 values (`answers.txt`):**

| Key | Value |
|---|---|
| `flag` | `FLAG{d6a67b896adcb8f1}` |
| `recovered_dh_b` | `172296553067`  (verified: `g^b mod p == B`) |
| `cracked_pin` | `cosmic769` |
| `nonce_xor_hex` | `0335282620446c382a3f2d6473180f1e1b2f0410561e` |

### 2.1 Negotiation: downgrade  (`TASKA1`)

**Weakness.** The hub's offered-suite list travels in clear, nothing binds it (no
MAC/signature over the negotiation), and one offered suite is `NULL` (no record
encryption). An on-path attacker rewrites the hub's `HELLO` to offer only `NULL`;
the lock has no strong option and selects `NULL`, so every record, including the
greeting that carries the flag, is plaintext on the wire.

**Evidence.** The capture shows `HELLO suites:NULL`, `SUITE suite:NULL`, and a `MSG`
whose `ct` hex-decodes to the greeting text (the flag in clear):

![Downgraded session: suite:NULL and the plaintext greeting on the wire](evidence/a1_downgrade_stream.png)

Tool output:

```
[downgrade] HELLO suites 'AES256-GCM,AES128-GCM,NULL' -> 'NULL'
[relay] *** flag = FLAG{d6a67b896adcb8f1} ***
[hub] negotiated suite: NULL
```

**Exploit.** `taska1` is an on-path TCP relay; `--downgrade` rewrites the `HELLO`
line in flight. Under `NULL` the lock sends each record's plaintext as the `ct`
field, so the flag is read with no key.

**Property broken.** Confidentiality (records are plaintext) and channel integrity
(the tampering with the negotiation was undetected).

### 2.2 Authentication: impersonation / MITM and the PIN  (`TASKA2`)

**Weakness (MITM).** The lock's certificate is self-signed and the hub never
validates it, and the DH values are unsigned. An attacker runs one key exchange
with the hub and another with the lock and relays between them, holding a separate
key with each side.

**Evidence.** Tool output: two **different** keys, flag read in clear, and active
tampering:

```
[mitm] key(hub)  = ...0d22eef048
[mitm] key(lock) = ...2501847f11
[mitm] *** flag = FLAG{d6a67b896adcb8f1} ***
[mitm] *** TAMPER: hub said LOCK -> sending UNLOCK ***
```

The hub's console shows a normal-looking session throughout, while the capture shows
the attacker-to-lock leg of the relayed handshake:

![MITM: the relayed handshake between the attacker and the lock](evidence/a2_mitm_stream.png)

**Exploit.** `taska2` plays the lock to the hub (presents a certificate and its own
DH value) and the hub to the lock (forwards the captured pinhash and its own DH
value), then decrypts/re-encrypts every record. `--tamper` turns the hub's `LOCK`
into `UNLOCK`.

**Property broken.** Authentication (and, through it, confidentiality and integrity
of the whole session).

**Weakness (PIN).** `PAIR` carries the PIN as a bare, unsalted MD5 digest. The PIN
is a dictionary word + three digits (86 words × 1000 = 86 000 candidates), so it
cracks instantly offline.

```
./pincrack session.txt smartlock/pin_wordlist.txt
[*] captured pinhash = 25f1d276cd99a2012752f0b0b6509a46
[+] cracked_pin = cosmic769
# equivalently:  hashcat -m 0 -a 6 pin.hash smartlock/pin_wordlist.txt ?d?d?d
```

**Property broken.** Confidentiality of the pairing credential.

### 2.3 Keying: discrete log, no KDF, static exponent  (`TASKA3`)

**Weakness.** The DH prime is ~40-bit (`dh_p = 780350106241`), so the discrete log
is solvable in moments by baby-step giant-step. v1 then uses the **raw** shared
secret as the AES key (no KDF), and the device reuses a **static** exponent `b`, so
recovering `b` once reconstructs the key of every session (no forward secrecy).

**Evidence / exploit.** `taska3` reads `p, g, B, A` from the capture, solves
`B = g^b (mod p)`, forms `s = A^b (mod p)`, derives the key exactly as
`session_key()` does, and decrypts the greeting:

```
[+] recovered_dh_b = 172296553067
[+] verify g^b mod p = 311997215343  (captured B = 311997215343)  -> MATCH
[+] record key     = ...2f623d2786
[+] flag = FLAG{d6a67b896adcb8f1}
```

**Property broken.** Confidentiality of the session key and forward secrecy. (The
missing KDF is a distinct weakness even if the group were large.)

### 2.4 Message protection: nonce reuse  (`TASKA4`)

**Weakness.** v1 uses one fixed nonce for every record under the same key. AES-GCM
is a stream cipher (`C = P XOR KS`), so reuse gives a two-time pad:
`C1 XOR C2 = P1 XOR P2`. The greeting's fixed known prefix recovers the keystream
and hence every other record (ciphertext only, no key).

**Evidence / exploit.** `taska4` confirms the shared nonce, lifts the keystream from
the known greeting prefix, and decrypts all records:

```
[+] every record reuses the same nonce 086421c21b34a824e019d43d
    [ 0] Paired with SmartLock. Pairing secret:
    [ 1] STATUS
    [ 2] STATE LOCKED unlocks=0
    [ 3] UNLOCK
    ...
[+] nonce_xor_hex = 0335282620446c382a3f2d6473180f1e1b2f0410561e
```

**Property broken.** Confidentiality and integrity of the records (GCM nonce reuse
also enables tag forgery, the "forbidden attack").

### 2.5 Teardown: replay  (`TASKA5`)

**Weakness.** Records carry no sequence number, the lock keeps no anti-replay state,
and there is no authenticated close. With a static exponent and static nonce, a
replayed handshake reproduces the same key, so a captured `UNLOCK` opens the door
again.

**Evidence / exploit.** `taska5` replays the captured hub handshake and `UNLOCK`
record to the live lock; the unlock counter climbs on each run:

```
run 1: [+] lock reply: DOOR OPENED (unlock #1)
run 2: [+] lock reply: DOOR OPENED (unlock #2)
```

The lock's own console confirms the door opened again from the replayed record, with
the persistent unlock counter climbing:

![Lock console: replayed UNLOCK opens the door again (unlock #1 then #2)](evidence/a5_counter.png)

**Property broken.** Integrity and availability (a command can no longer be trusted
to happen once and only once).

---

## 3. Part B: Designing SmartLock v2

### 3.1 Threat model

**Attacker.** A Dolev-Yao on-path adversary on the home LAN (a guest on the Wi-Fi, a
compromised device, or a neighbour who joined it). They can **see, drop, modify,
inject, and replay** any message between hub and lock, and can run their own
clients/servers. They **do not** possess the lock's RSA private key, the pairing
PIN, or either party's ephemeral DH secret, and cannot break standard primitives
(AES-GCM, SHA-256, RSA-2048, 2048-bit DH).

**Security goals for v2.**
- **Confidentiality + integrity** of every command and reply (AEAD).
- **Authentication** of the lock to the hub (no impersonation / MITM).
- **A protected negotiation** (no downgrade; NULL never selectable).
- **Forward secrecy** (a later key compromise must not expose past sessions).
- **Freshness** (no replay or reordering of records; an authenticated close).
- **Credential protection** for the PIN, on the wire and at rest.

### 3.2 Per-stage mechanism (each tied to the Part A attack it defeats)

| Stage | Mechanism in v2 | Defeats |
|---|---|---|
| Negotiation | `strong_suites()` offers **only** AEAD suites; `choose_suite()` picks the strongest common one and **aborts** (`""`) rather than downgrade - `NULL` is never selectable. The device **signs the transcript** `offer\|suite\|B`, so any tampering with the offered list is detected. | A1 downgrade |
| Authentication | The hub **pins** the device's RSA public key and **verifies the certificate signature**; it rejects any key that is not the pinned one. The PIN is sent as a **salted, slow KDF** digest (Argon2id, or PBKDF2/scrypt) - never bare MD5 - and stored only in that form on the device. | A2 MITM + PIN |
| Keying | **Fresh ephemeral 2048-bit DH** every session (RFC 3526 group) → the discrete log is infeasible and past sessions stay safe (forward secrecy). The shared secret is run through **HKDF-SHA256** to produce the record key - not used raw. The device **signs its DH value**, so a MITM cannot substitute it. | A3 keying |
| Message protection | **AES-GCM AEAD** with a **unique nonce per record**: `nonce = 0x00000000 ‖ seqno(64-bit BE)`, so no `(key, nonce)` pair is ever reused. Separate keys per direction (HKDF `info` = `c2s` / `s2c`). | A4 nonce reuse |
| Teardown | Each record **binds a per-direction 64-bit sequence number** as AEAD associated data and transmits it; `open_record()` **rejects** any record whose sequence number is not the expected next one, so replays and reordering fail. A `QUIT` is itself a sequence-bound, authenticated record, giving an authenticated close. | A5 replay |

**PIN protection (design requirement; the scaffold does not implement it).** v2 must
never transmit or store a bare MD5 PIN hash. Instead, at provisioning the device
stores `Argon2id(salt, PIN)` (a unique random salt, memory-hard parameters). At
pairing the hub proves knowledge of the PIN inside the already-authenticated,
encrypted channel (e.g. a PAKE such as SPAKE2, or at minimum sending the PIN only
after the device is authenticated and the channel is confidential), so an attacker
who captures the pairing cannot mount the offline dictionary attack of §2.2.

### 3.3 v2 handshake diagram

```
        HUB (controller)                                  LOCK (device)
          |                                                   |
   (1)    |----- HELLO  suites = {AES256-GCM, AES128-GCM} --->|   negotiation
          |                                                   |   (no NULL offered)
   (2)    |<---- SUITE  suite ------------------------------  |   choose_suite(), abort
          |                                                   |   rather than downgrade
   (3)    |<---- CERT   name, pubkey, sig ------------------- |   AUTHENTICATION
          |   pin pubkey == pinned key; verify sig            |   (signed cert)
   (4)    |----- PAIR   hub, pin-proof --------------------->|   (PIN via salted KDF
          |                                                   |    / PAKE; design)
   (5)    |<---- DH     B=g^b, sig(offer|suite|B) ----------  |   KEYING: fresh 2048-bit
          |   verify sig over transcript  (binds negotiation) |   ephemeral b; signs B
   (6)    |----- DHCLIENT  A=g^a --------------------------->|   fresh ephemeral a
          |                                                   |
          |   s = DH(A,B);  k_c2s = HKDF(s,"c2s")             |   KEY DERIVATION (HKDF)
          |                 k_s2c = HKDF(s,"s2c")             |   per-direction keys
          |                                                   |
   (7)    |<---- MSG rec = seal(k_s2c, seq=0, greeting) ----- |   RECORDS: AEAD, nonce =
          |                                                   |   f(seq), seq bound as AAD
   (8)    |----- MSG rec = seal(k_c2s, seq=0, "STATUS") ---->|   SEQUENCE BINDING
   (9)    |<---- MSG rec = seal(k_s2c, seq=1, reply) -------- |   open_record() rejects
          |            ... each record seq increments ...     |   any unexpected seq
  (10)    |----- MSG rec = seal(k_c2s, seq=n, "QUIT") ------>|   authenticated close
```

Record layout produced by `seal()`: `seqno(8 B, big-endian) ‖ ciphertext ‖ GCM tag(16 B)`.

---

## 4. Part C: Implementing and testing v2

The security core `securelink2.cpp` implements the module contract: `strong_suites`,
`choose_suite`, `derive_key` (HKDF-SHA256), `make_nonce`, `seal`, `open_record`.

### 4.1 C.1: the six checks

Self-test `v2_skeleton/securelink2_selftest.cpp` → **19/19 assertions pass**:

```
Check 1 - suite policy: NULL-only refused; picks AES256; AES128 not NULL; empty aborts
Check 2 - key derivation: HKDF, 32/16 B, != raw secret, deterministic, c2s != s2c
Check 3 - unique nonce: 12 B; 100000 seqnos -> 100000 distinct nonces
Check 4 - AEAD round-trip: open(seal(pt)) == pt (AES256, AES128, empty)
Check 5 - replay/reorder/tamper: wrong seq throws; tag/seq tamper throws; correct opens
Check 6 - source scan: has 'hkdf'; 0x 'md5' (any case); 0x 'TODO'
```

A normal `lock_server2` / `hub_client2` session succeeds (greeting + STATUS/UNLOCK/LOCK).

### 4.2 C.2: v1 attacks re-run against v2

| v1 attack | v2 result | How shown |
|---|---|---|
| A1 downgrade | **Fails**: `ALERT no acceptable suite`; hub aborts `no suite` | relay `--downgrade` vs `lock_server2` |
| A2 impersonation / MITM | **Fails**: hub aborts `DH value not authenticated` (signed DH; pinned cert) | relay `--corrupt-dh` vs hub2 |
| A3 keying recovery | **Fails**: DH `B` is a fresh **2048-bit** ephemeral, different each session (512 hex chars); no small prime, no static exponent | capture two v2 sessions |
| A4 nonce reuse | **Fails**: every record carries a distinct sequence number / nonce (`0,1,2,…` per direction) | inspect `rec` headers |
| A5 replay / reorder / tamper | **Fails**: the lock drops the session (`open_record` throws) | `v2_attack_demo replay/reorder/tamper` |

Normal session succeeds; tampered, replayed, and reordered records are each rejected
(`v2_attack_demo baseline/tamper/replay/reorder` all print **PASS**).

### 4.3 AI-audit component

I asked an AI assistant to write the record layer (`seal`/`open_record`). The code it
produced was broadly correct (AES-GCM with the sequence number as associated data),
but it contained a **real cryptographic-plumbing bug** in `open_record`. For the
authenticated-data pass it wrote `EVP_DecryptUpdate(ctx, NULL, &len, aad, 8)` and then
reused that same `len` as the start of the output length. In GCM, the AAD call sets
`len` to the AAD byte count (8). For ordinary records the subsequent ciphertext
`DecryptUpdate` overwrites `len`, hiding the mistake, but for an **empty-plaintext**
record the ciphertext update is skipped, so the stale `len = 8` leaked through and
`open_record` returned **8 bytes of uninitialised buffer** instead of an empty string
(and would have mis-sized the output in general). My self-test's empty-plaintext case
caught it. I corrected it by giving the AAD pass its own throwaway length and tracking
the real output length (`outl`) only from the ciphertext and final calls. Lesson: AI
crypto code tends to be right on the common path and wrong on edge cases (empty input,
length accounting, nonce/AAD handling), so it must be driven by property tests, not
read for plausibility.

---

## 5. Part D: Performance study

**Machine / method.** Measured on an Intel Core i7-1185G7 @ 3.00 GHz (x86_64, with
AES-NI), Kali GNU/Linux Rolling (kernel 6.x), inside the VMware lab VM. Both versions
built with the same flags (`-std=c++17 -O2 -Wall`, OpenSSL 3.x). Record micro-benchmarks
are in-process; handshake timing is networked (TCP connect to greeting decrypted). Tool:
`performance/23i-0652-G-TASKD-V1.cpp`; chart: `performance/chart.png`.

**Handshake (30 runs, mean ± sd):**

| Version | Handshake |
|---|---|
| v1 (40-bit DH, no auth) | **1.64 ± 0.55 ms** |
| v2 (2048-bit ephemeral DH + RSA sign/verify) | **3.23 ± 0.68 ms** |

**Per-record overhead and throughput (1 KiB records):**

| | v1 | v2 |
|---|---|---|
| crypto expansion | +16 B tag (+12 B nonce sent separately) | +8 B seq +16 B tag |
| wire line (1 KiB pt) | 2124 B | 2110 B |
| seal latency | 0.91 ± 0.62 µs | 0.65 ± 0.42 µs |
| open latency | 0.86 ± 0.39 µs | 0.85 ± 0.33 µs |
| seal throughput | ~1107 ± 24 MB/s | ~1479 ± 90 MB/s |
| open throughput | ~1201 ± 8 MB/s | ~1076 ± 38 MB/s |

![v1 vs v2 performance](performance/chart.png)

**Trade-off.** The entire security cost is paid **once per session**: v2's handshake
is about **0.9 ms slower** than v1's (roughly 2x: ~2.05 ms vs ~1.12 ms) because it
replaces a trivially breakable 40-bit DH with a fresh 2048-bit ephemeral exchange and
adds an RSA signature and verification for authentication. The **per-record** cost is
comparable: both use hardware-accelerated AES-GCM, so seal/open latency and throughput
stay in the same range (on this machine v2 even seals faster), and v2's wire record is
actually a little **smaller** (it carries an 8-byte sequence number instead of v1's
separately transmitted 12-byte nonce). For a device that controls a front door, under a
millisecond added to an action that already involves a motor turning a bolt is imperceptible, while
what it buys is decisive: confidentiality and integrity of every command, authentication
of the lock, forward secrecy, and the end of replay: a captured `UNLOCK` is no
longer a skeleton key. For this threat model the trade-off is clearly correct.
