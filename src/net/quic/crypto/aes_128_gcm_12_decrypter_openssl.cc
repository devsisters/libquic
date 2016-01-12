// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/aes_128_gcm_12_decrypter.h"

#include <openssl/evp.h>
#include <openssl/tls1.h>

namespace net {

namespace {

const size_t kKeySize = 16;
const size_t kNoncePrefixSize = 4;

}  // namespace

Aes128Gcm12Decrypter::Aes128Gcm12Decrypter()
    : AeadBaseDecrypter(EVP_aead_aes_128_gcm(),
                        kKeySize,
                        kAuthTagSize,
                        kNoncePrefixSize) {
  static_assert(kKeySize <= kMaxKeySize, "key size too big");
  static_assert(kNoncePrefixSize <= kMaxNoncePrefixSize,
                "nonce prefix size too big");
}

Aes128Gcm12Decrypter::~Aes128Gcm12Decrypter() {}

const char* Aes128Gcm12Decrypter::cipher_name() const {
  return TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
}

uint32_t Aes128Gcm12Decrypter::cipher_id() const {
  // This OpenSSL macro has the value 0x0300C02F. The two most significant bytes
  // 0x0300 are OpenSSL specific and are NOT part of the TLS CipherSuite value
  // for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.
  return TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
}

}  // namespace net
