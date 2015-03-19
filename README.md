QUIC, a multiplexed stream transport over UDP
=============================================

QUIC is an experimental protocol aimed at reducing web latency over that of TCP.
On the surface, QUIC is very similar to TCP+TLS+SPDY implemented on UDP. Because
TCP is implement in operating system kernels, and middlebox firmware, making
significant changes to TCP is next to impossible. However, since QUIC is built
on top of UDP, it suffers from no such limitations.

Key features of QUIC over existing TCP+TLS+SPDY include

  * Dramatically reduced connection establishment time
  * Improved congestion control
  * Multiplexing without head of line blocking
  * Forward error correction
  * Connection migration

See [Chromium QUIC Page](http://www.chromium.org/quic) for detailed information.

## libquic

This repository is sources and dependencies extracted from
[Chromium's QUIC Implementation](https://chromium.googlesource.com/chromium/src.git/+/master/net/quic/)
with a few modifications and patches to minimize dependencies needed to build
QUIC library.

Notable and only dependency is [BoringSSL](https://boringssl.googlesource.com/).
The BoringSSL sources is already embedded in this repository and linked with
CMake build file. You don't need any kind of dependency installs.

## Language Bindings

This library is intended as an essential reference point for other language
bindings and possibly for integration with other C/C++ codebase such as HTTP
servers like Apache or nginx.

Currently there is only one experimental language binding:

  * Go binding: [goquic](https://github.com/devsisters/goquic)


Getting Started
===============

## How to build

Building with CMake and [Ninja](http://martine.github.io/ninja/) (Recommended):

```bash
$ mkdir build/
$ cd build/
$ cmake -GNinja ..
$ ninja
```

Building with CMake and Make:

```bash
$ mkdir build/
$ cd build/
$ cmake ..
$ make -j
```

`libquic.a` library file will be generated. `libssl.a`, `libcrypto.a` will be
located in build/boringssl directory.

To do release builds run `$ cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..` instead
of `$ cmake -GNinja ..`.

## How to integrate

In order to integrate libquic to your code, your best source of documentation is
official Chromium QUIC toy client and server. Golang binding will help too.

  * [QUIC toy client and server](http://www.chromium.org/quic/playing-with-quic)
  * [goquic C++ code](https://github.com/devsisters/goquic/tree/master/src)

## Syncing from Upstream

Great effort has been made to make syncing from upstream Chromium sources as
effortless as possible. See `DEPS` file for all the dependencies. See
`manage.py` script for actual syncing.

If you want to apply upstream chnages,

  1. Clone & Checkout chromium upstream. Update "chromium_revision" var at DEPS
     to your chromium source code revision.
  2. Do `./manage.py sync <CHROMIUM_GIT_ROOT>`
     Then, all necessary files will be updated to new one.
  3. If there is any patch collision, fix it and repeat `step 2`.
  4. Temporarily commit here. Try build, and you'll find that you may need to
     add additional patches.
  5. Do your work, then make a patch by `git diff > new_patch.patch`
  6. Add patch file to `DEPS`. Amend previous temp commit.
  7. Commit `DEPS`, new patch, and source changes

