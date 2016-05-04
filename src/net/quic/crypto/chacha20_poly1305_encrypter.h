// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_CHACHA20_POLY1305_ENCRYPTER_H_
#define NET_QUIC_CRYPTO_CHACHA20_POLY1305_ENCRYPTER_H_

#include <stddef.h>

#include "base/macros.h"
#include "net/quic/crypto/aead_base_encrypter.h"

namespace net {

// A ChaCha20Poly1305Encrypter is a QuicEncrypter that implements the
// AEAD_CHACHA20_POLY1305 algorithm specified in
// draft-agl-tls-chacha20poly1305-04, except that it truncates the Poly1305
// authenticator to 12 bytes. Create an instance by calling
// QuicEncrypter::Create(kCC12).
//
// It uses an authentication tag of 16 bytes (128 bits). There is no
// fixed nonce prefix.
class NET_EXPORT_PRIVATE ChaCha20Poly1305Encrypter : public AeadBaseEncrypter {
 public:
  enum {
    kAuthTagSize = 12,
  };

  ChaCha20Poly1305Encrypter();
  ~ChaCha20Poly1305Encrypter() override;

 private:
  DISALLOW_COPY_AND_ASSIGN(ChaCha20Poly1305Encrypter);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_CHACHA20_POLY1305_ENCRYPTER_H_
