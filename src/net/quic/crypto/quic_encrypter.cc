// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/quic_encrypter.h"

#include "net/quic/crypto/aes_128_gcm_12_encrypter.h"
#include "net/quic/crypto/chacha20_poly1305_encrypter.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/null_encrypter.h"

namespace net {

// static
QuicEncrypter* QuicEncrypter::Create(QuicTag algorithm) {
  switch (algorithm) {
    case kAESG:
      return new Aes128Gcm12Encrypter();
    case kCC20:
      return new ChaCha20Poly1305Encrypter();
    case kNULL:
      return new NullEncrypter();
    default:
      LOG(FATAL) << "Unsupported algorithm: " << algorithm;
      return nullptr;
  }
}

}  // namespace net
