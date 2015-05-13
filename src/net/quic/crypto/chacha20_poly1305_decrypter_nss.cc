// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/chacha20_poly1305_decrypter.h"

#include <pk11pub.h>

#include "base/logging.h"

using base::StringPiece;

namespace net {

namespace {

const size_t kKeySize = 32;
const size_t kNoncePrefixSize = 0;

}  // namespace

#if defined(USE_NSS_CERTS)

// System NSS doesn't support ChaCha20+Poly1305 yet.

ChaCha20Poly1305Decrypter::ChaCha20Poly1305Decrypter()
    : AeadBaseDecrypter(CKM_INVALID_MECHANISM, nullptr, kKeySize,
                        kAuthTagSize, kNoncePrefixSize) {
  NOTIMPLEMENTED();
}

ChaCha20Poly1305Decrypter::~ChaCha20Poly1305Decrypter() {}

// static
bool ChaCha20Poly1305Decrypter::IsSupported() {
  return false;
}

void ChaCha20Poly1305Decrypter::FillAeadParams(
    StringPiece nonce,
    const StringPiece& associated_data,
    size_t auth_tag_size,
    AeadParams* aead_params) const {
  NOTIMPLEMENTED();
}

#else  // defined(USE_NSS_CERTS)

ChaCha20Poly1305Decrypter::ChaCha20Poly1305Decrypter()
    : AeadBaseDecrypter(CKM_NSS_CHACHA20_POLY1305, PK11_Decrypt, kKeySize,
                        kAuthTagSize, kNoncePrefixSize) {
  static_assert(kKeySize <= kMaxKeySize, "key size too big");
  static_assert(kNoncePrefixSize <= kMaxNoncePrefixSize,
                "nonce prefix size too big");
}

ChaCha20Poly1305Decrypter::~ChaCha20Poly1305Decrypter() {}

// static
bool ChaCha20Poly1305Decrypter::IsSupported() {
  return true;
}

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

#endif  // defined(USE_NSS_CERTS)

}  // namespace net
