#!/usr/bin/env bash

rm -fr build
mkdir -p build
cd build
cmake -GNinja ..
ninja
cp boringssl/crypto/libcrypto.a boringssl/ssl/libssl.a .

echo "libquic.a libcrypto.a libssl.a is now in ./build directory"
