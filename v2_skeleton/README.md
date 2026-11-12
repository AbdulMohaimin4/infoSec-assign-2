# SmartLock v2 Skeleton: What to Build

This folder is where you implement the corrected system (v2). On submission your
`securelink2.cpp` is compiled, linked, and checked automatically for the six
items listed below, so the division of work is clear.

## What you implement

**`securelink2.cpp`** (the graded module). Implement every function declared in
`securelink2.hpp`, keeping each name and signature. Their contracts are in the
header comments. In short:

- `strong_suites()`: the suites you accept. Must never include `NULL`.
- `choose_suite(...)`: a negotiation policy that picks the strongest common
  suite, never `NULL`, and returns `""` (abort) rather than downgrade.
- `derive_key(...)`: derive the record key from the Diffie-Hellman secret with a
  KDF (for example HKDF-SHA256). Do not return the raw secret. The `context`
  argument lets you derive a separate key per direction.
- `make_nonce(...)`: a unique 12-byte nonce per sequence number under a key.
- `seal(...)` and `open_record(...)`: AEAD protection that binds the sequence
  number, so a replayed or out-of-order record is rejected (`open_record` throws
  when the sequence number is not the expected one).

Suggested OpenSSL building blocks: `EVP_aes_256_gcm` / `EVP_aes_128_gcm` for the
AEAD, and `EVP_KDF` with `"HKDF"` for the key. You may add private helpers.

**Known limitation: the pairing PIN.** The provided scaffold still sends the v1
MD5 `pinhash` in `PAIR`, so PIN cracking still works against v2 and is not part of
your C.2 table. You do not have to implement a fix. Your Part B design must say how
v2 should protect the PIN, both on the wire and at rest (at rest, use a salted, slow
KDF such as PBKDF2, scrypt, or Argon2, never raw MD5).

## What is provided (do not change the interface)

- `lock_server2.cpp` and `hub_client2.cpp`: the handshake plumbing is provided
  and calls your `securelink2.cpp`. They already use a strong ephemeral
  Diffie-Hellman group (RFC 3526 2048-bit, in `dh2048.hpp`), sign the device DH
  value for authentication, pin and validate the device certificate, and run the
  sequence-numbered record loop. Once `securelink2.cpp` is complete, they build
  and run.
- `dh2048.hpp`: the strong ephemeral DH group. No policy for you here.
- `slink.hpp`, `pki.hpp`: the line framing and the RSA helpers. No crypto policy
  here.

You may extend `lock_server2.cpp` and `hub_client2.cpp`, but keep the message
types (`HELLO`, `SUITE`, `CERT`, `PAIR`, `DH`, `DHCLIENT`, `MSG`) and the CLI
(`./lock_server2 instance.txt`) so the submission check and your own hub can
still talk to the lock. Submit any changed file under `v2_changes/`, as the
Statement describes.

## Building and running v2

```
make
./lock_server2 ../smartlock/instance.txt
./hub_client2 ../smartlock/instance.txt 127.0.0.1
```

As in v1, the hub takes an optional port after the host, and the door state and
unlock counter last until `lock_server2` restarts. Once `securelink2.cpp` is
complete, a normal session runs exactly like the v1
one, but the handshake is authenticated and every record is sequence-bound.

## What is checked (Part C.1)

Your `securelink2.cpp` is marked against six checks, 3 marks each, verified
automatically on submission. Confirm each one yourself with your own test program and include
that output in your report:

1. it never selects `NULL` and never downgrades below the agreed suite;
2. it derives the record key from the Diffie-Hellman secret with a KDF, not the
   raw secret;
3. it uses a unique nonce per record under a key;
4. its AEAD seals a record and opens it back correctly;
5. it rejects a replayed or out-of-order record (`open_record` throws when the
   sequence number is not the expected one); and
6. a source scan: the file contains one of `hkdf`, `evp_kdf`, `pbkdf2`, or `scrypt`,
   and does not contain `md5` (in any letter case) or `TODO`, including in comments.

A quick way to exercise these is a short `main()` of your own that calls
`strong_suites`, `choose_suite`, `derive_key`, `make_nonce`, `seal`, and
`open_record` and prints the result of each property. Do not use raw MD5 anywhere
in this module, and do not leave any function unimplemented.
