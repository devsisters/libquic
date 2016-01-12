// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/chacha20_poly1305_rfc7539_encrypter.h"

#include <openssl/evp.h>

namespace net {

namespace {

const size_t kKeySize = 32;
const size_t kNoncePrefixSize = 4;

}  // namespace

ChaCha20Poly1305Rfc7539Encrypter::ChaCha20Poly1305Rfc7539Encrypter()
    : AeadBaseEncrypter(EVP_aead_chacha20_poly1305_rfc7539(),
                        kKeySize,
                        kAuthTagSize,
                        kNoncePrefixSize) {
  static_assert(kKeySize <= kMaxKeySize, "key size too big");
  static_assert(kNoncePrefixSize <= kMaxNoncePrefixSize,
                "nonce prefix size too big");
}

ChaCha20Poly1305Rfc7539Encrypter::~ChaCha20Poly1305Rfc7539Encrypter() {}

bool ChaCha20Poly1305Rfc7539Encrypter::IsSupported() {
  return true;
}

}  // namespace net
