// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/chacha20_poly1305_decrypter.h"

#include <openssl/evp.h>
#include <openssl/tls1.h>

namespace net {

namespace {

const size_t kKeySize = 32;
const size_t kNoncePrefixSize = 0;

}  // namespace

// QUIC currently uses the draft-agl-tls-chacha20poly1305-04 ChaCha20-Poly1305
// construction rather than RFC 7539.
ChaCha20Poly1305Decrypter::ChaCha20Poly1305Decrypter()
    : AeadBaseDecrypter(EVP_aead_chacha20_poly1305_old(),
                        kKeySize,
                        kAuthTagSize,
                        kNoncePrefixSize) {
  static_assert(kKeySize <= kMaxKeySize, "key size too big");
  static_assert(kNoncePrefixSize <= kMaxNoncePrefixSize,
                "nonce prefix size too big");
}

ChaCha20Poly1305Decrypter::~ChaCha20Poly1305Decrypter() {}

const char* ChaCha20Poly1305Decrypter::cipher_name() const {
  return TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305_OLD;
}

uint32_t ChaCha20Poly1305Decrypter::cipher_id() const {
  return TLS1_CK_ECDHE_RSA_CHACHA20_POLY1305_OLD;
}

}  // namespace net
