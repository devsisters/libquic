// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/chacha20_poly1305_decrypter.h"

#include <pk11pub.h>

using base::StringPiece;

namespace net {

namespace {

const size_t kKeySize = 32;
const size_t kNoncePrefixSize = 0;

}  // namespace

ChaCha20Poly1305Decrypter::ChaCha20Poly1305Decrypter()
    : AeadBaseDecrypter(CKM_NSS_CHACHA20_POLY1305,
                        kKeySize,
                        kAuthTagSize,
                        kNoncePrefixSize) {
  static_assert(kKeySize <= kMaxKeySize, "key size too big");
  static_assert(kNoncePrefixSize <= kMaxNoncePrefixSize,
                "nonce prefix size too big");
}

ChaCha20Poly1305Decrypter::~ChaCha20Poly1305Decrypter() {}

void ChaCha20Poly1305Decrypter::FillAeadParams(
    StringPiece nonce,
    const StringPiece& associated_data,
    size_t auth_tag_size,
    AeadParams* aead_params) const {
  aead_params->len = sizeof(aead_params->data.nss_aead_params);
  CK_NSS_AEAD_PARAMS* nss_aead_params = &aead_params->data.nss_aead_params;
  nss_aead_params->pIv =
      reinterpret_cast<CK_BYTE*>(const_cast<char*>(nonce.data()));
  nss_aead_params->ulIvLen = nonce.size();
  nss_aead_params->pAAD =
      reinterpret_cast<CK_BYTE*>(const_cast<char*>(associated_data.data()));
  nss_aead_params->ulAADLen = associated_data.size();
  nss_aead_params->ulTagLen = auth_tag_size;
}

const char* ChaCha20Poly1305Decrypter::cipher_name() const {
  // TODO(rtenneti): Use TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305 instead of
  // hard coded string.
  // return TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305;
  return "ECDHE-RSA-CHACHA20-POLY1305";
}

uint32_t ChaCha20Poly1305Decrypter::cipher_id() const {
  // TODO(rtenneti): when Chromium requires NSS 3.15.2 or later, use
  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 instead of 0xCC13.
  // "OR" 0x03000000 to match OpenSSL/BoringSSL implementations.
  return 0x03000000 | 0xCC13;
}

}  // namespace net
