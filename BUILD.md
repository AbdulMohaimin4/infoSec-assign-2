# Toolchain and build

Everything here is C++17 and links OpenSSL's `libcrypto`. There is no third-party
library beyond OpenSSL.

## Dependencies (once)

On Kali or Debian/Ubuntu:

```
sudo apt install build-essential libssl-dev
```

`g++` 11 or newer is expected. Check with `g++ --version`.

## Build

Each folder has a `Makefile`:

```
make -C smartlock          # v1 lock, hub, and the instance generator (what you attack)
make -C v2_skeleton        # v2 lock and hub, built against your securelink2.cpp
```

## Generate your instance (once)

Create your own `instance.txt` from your roll number:

```
cd smartlock
./instance_generator 23i-0001      # use your own roll; writes instance.txt
```

## Run

Run v1 from inside `smartlock/`, where `instance.txt` was written:

```
cd smartlock
./lock_server instance.txt                 # terminal 1 (or VM 1)
./hub_client  instance.txt <host> [port]   # terminal 2 (or VM 2)
```

Run v2 from inside `v2_skeleton/`, using the same instance:

```
cd v2_skeleton
./lock_server2 ../smartlock/instance.txt
./hub_client2  ../smartlock/instance.txt <host> [port]
```

Use `127.0.0.1` for a single-host smoke test, and the lock VM's address for the lab
in `Lab_Setup_Guide.pdf`. The hub connects to the port in `instance.txt` unless you
give the optional `port`, for example to point it at a relay.
