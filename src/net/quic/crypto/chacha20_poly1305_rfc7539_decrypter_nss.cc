// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/chacha20_poly1305_rfc7539_decrypter.h"

#include <pk11pub.h>

using base::StringPiece;

namespace net {

namespace {

const size_t kKeySize = 32;
const size_t kNoncePrefixSize = 4;

}  // namespace

ChaCha20Poly1305Rfc7539Decrypter::ChaCha20Poly1305Rfc7539Decrypter()
    : AeadBaseDecrypter(CKM_NSS_CHACHA20_POLY1305,
                        kKeySize,
                        kAuthTagSize,
                        kNoncePrefixSize) {
  static_assert(kKeySize <= kMaxKeySize, "key size too big");
  static_assert(kNoncePrefixSize <= kMaxNoncePrefixSize,
                "nonce prefix size too big");
}

ChaCha20Poly1305Rfc7539Decrypter::~ChaCha20Poly1305Rfc7539Decrypter() {}

bool ChaCha20Poly1305Rfc7539Decrypter::IsSupported() {
  return false;
}

const char* ChaCha20Poly1305Rfc7539Decrypter::cipher_name() const {
  return "";
}

uint32_t ChaCha20Poly1305Rfc7539Decrypter::cipher_id() const {
  return 0;
}

void ChaCha20Poly1305Rfc7539Decrypter::FillAeadParams(
    base::StringPiece nonce,
    const base::StringPiece& associated_data,
    size_t auth_tag_size,
    AeadParams* aead_params) const {}

}  // namespace net
