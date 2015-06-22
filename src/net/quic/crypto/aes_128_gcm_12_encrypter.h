// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_AES_128_GCM_12_ENCRYPTER_H_
#define NET_QUIC_CRYPTO_AES_128_GCM_12_ENCRYPTER_H_

#include "net/quic/crypto/aead_base_encrypter.h"

namespace net {

// An Aes128Gcm12Encrypter is a QuicEncrypter that implements the
// AEAD_AES_128_GCM_12 algorithm specified in RFC 5282. Create an instance by
// calling QuicEncrypter::Create(kAESG).
//
// It uses an authentication tag of 12 bytes (96 bits). The fixed prefix
// of the nonce is four bytes.
class NET_EXPORT_PRIVATE Aes128Gcm12Encrypter : public AeadBaseEncrypter {
 public:
  enum {
    // Authentication tags are truncated to 96 bits.
    kAuthTagSize = 12,
  };

  Aes128Gcm12Encrypter();
  ~Aes128Gcm12Encrypter() override;

#if !defined(USE_OPENSSL)
 protected:
  // AeadBaseEncrypter methods:
  void FillAeadParams(base::StringPiece nonce,
                      base::StringPiece associated_data,
                      size_t auth_tag_size,
                      AeadParams* aead_params) const override;
#endif

 private:
  DISALLOW_COPY_AND_ASSIGN(Aes128Gcm12Encrypter);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_AES_128_GCM_12_ENCRYPTER_H_
