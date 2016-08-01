QUIC, a multiplexed stream transport over UDP
=============================================

QUIC is an experimental protocol aimed at reducing web latency over that of TCP.
On the surface, QUIC is very similar to TCP+TLS+SPDY implemented on UDP. Because
TCP is implemented in operating system kernels, and middlebox firmware, making
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

Building with CMake and [Ninja](https://ninja-build.org/) (Recommended):

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
$ make -j 4
```
make -j <numOfRecepies> limits the number of simultaneously executed Recepies. Adapt this number to the capabilities of your build machine.

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

If you want to apply upstream changes,

  1. Clone & Checkout chromium upstream.
  2. Build QUIC server: `cd out/Debug; ninja quic_server`
  3. Update "chromium_revision" var at DEPS to your chromium source code
     revision.
  4. Do `./sync.py <CHROMIUM_GIT_ROOT>`
     All necessary files will be updated to new ones without patches applied.
  5. Temporarily commit here.
  6. Do `./sync.py <CHROMIUM_GIT_ROOT>`--patch
     All the patches will be applied. Some patches will be rejected.
  7. If there is any patch collision, manually apply the rejected patches.
     Open the `*.rej` files and carefully apply the rejected hunks manually.
  8. Try build, and you'll find that you may need to add additional
     modifications to make build successful. There may be added or deleted
     source files. Update `CMakeLists.txt` accordingly.
  9. If the build is successful, make a patch by:
     `git diff src/ > patch/basepatch.patch`
     (Make sure you don't include `custom/` directory sources to the patch)
  10. Add patch file to `DEPS` or update existing patch files. Amend previous
      commit.
  11. Commit `DEPS`, new patch, and source changes

