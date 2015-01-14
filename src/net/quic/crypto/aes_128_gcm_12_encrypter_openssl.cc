// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/aes_128_gcm_12_encrypter.h"

#include <openssl/evp.h>

namespace net {

namespace {

const size_t kKeySize = 16;
const size_t kNoncePrefixSize = 4;

}  // namespace

Aes128Gcm12Encrypter::Aes128Gcm12Encrypter()
    : AeadBaseEncrypter(EVP_aead_aes_128_gcm(), kKeySize, kAuthTagSize,
                        kNoncePrefixSize) {
  COMPILE_ASSERT(kKeySize <= kMaxKeySize, key_size_too_big);
  COMPILE_ASSERT(kNoncePrefixSize <= kMaxNoncePrefixSize,
                 nonce_prefix_size_too_big);
}

Aes128Gcm12Encrypter::~Aes128Gcm12Encrypter() {}

}  // namespace net
