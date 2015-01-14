// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/chacha20_poly1305_encrypter.h"

#include <openssl/evp.h>

namespace net {

namespace {

const size_t kKeySize = 32;
const size_t kNoncePrefixSize = 0;

}  // namespace

ChaCha20Poly1305Encrypter::ChaCha20Poly1305Encrypter()
    : AeadBaseEncrypter(EVP_aead_chacha20_poly1305(), kKeySize, kAuthTagSize,
                        kNoncePrefixSize) {
  COMPILE_ASSERT(kKeySize <= kMaxKeySize, key_size_too_big);
  COMPILE_ASSERT(kNoncePrefixSize <= kMaxNoncePrefixSize,
                 nonce_prefix_size_too_big);
}

ChaCha20Poly1305Encrypter::~ChaCha20Poly1305Encrypter() {}

// static
bool ChaCha20Poly1305Encrypter::IsSupported() { return true; }

}  // namespace net
