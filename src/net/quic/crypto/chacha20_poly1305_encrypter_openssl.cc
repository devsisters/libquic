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

// QUIC currently uses the draft-agl-tls-chacha20poly1305-04 ChaCha20-Poly1305
// construction rather than RFC 7539.
ChaCha20Poly1305Encrypter::ChaCha20Poly1305Encrypter()
    : AeadBaseEncrypter(EVP_aead_chacha20_poly1305_old(),
                        kKeySize,
                        kAuthTagSize,
                        kNoncePrefixSize) {
  static_assert(kKeySize <= kMaxKeySize, "key size too big");
  static_assert(kNoncePrefixSize <= kMaxNoncePrefixSize,
                "nonce prefix size too big");
}

ChaCha20Poly1305Encrypter::~ChaCha20Poly1305Encrypter() {}

}  // namespace net
