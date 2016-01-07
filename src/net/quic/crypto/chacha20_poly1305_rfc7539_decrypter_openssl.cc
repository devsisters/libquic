// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/chacha20_poly1305_rfc7539_decrypter.h"

#include <openssl/evp.h>
#include <openssl/tls1.h>

namespace net {

namespace {

const size_t kKeySize = 32;
const size_t kNoncePrefixSize = 4;

}  // namespace

ChaCha20Poly1305Rfc7539Decrypter::ChaCha20Poly1305Rfc7539Decrypter()
    : AeadBaseDecrypter(EVP_aead_chacha20_poly1305_rfc7539(),
                        kKeySize,
                        kAuthTagSize,
                        kNoncePrefixSize) {
  static_assert(kKeySize <= kMaxKeySize, "key size too big");
  static_assert(kNoncePrefixSize <= kMaxNoncePrefixSize,
                "nonce prefix size too big");
}

ChaCha20Poly1305Rfc7539Decrypter::~ChaCha20Poly1305Rfc7539Decrypter() {}

bool ChaCha20Poly1305Rfc7539Decrypter::IsSupported() {
  return true;
}

const char* ChaCha20Poly1305Rfc7539Decrypter::cipher_name() const {
  return TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305_OLD;
}

uint32_t ChaCha20Poly1305Rfc7539Decrypter::cipher_id() const {
  return TLS1_CK_ECDHE_RSA_CHACHA20_POLY1305_OLD;
}

}  // namespace net
