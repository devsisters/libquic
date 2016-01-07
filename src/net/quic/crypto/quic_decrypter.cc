// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/quic_decrypter.h"

#include "net/quic/crypto/aes_128_gcm_12_decrypter.h"
#include "net/quic/crypto/chacha20_poly1305_decrypter.h"
#include "net/quic/crypto/chacha20_poly1305_rfc7539_decrypter.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/null_decrypter.h"

namespace net {

// static
QuicDecrypter* QuicDecrypter::Create(QuicTag algorithm) {
  switch (algorithm) {
    case kAESG:
      return new Aes128Gcm12Decrypter();
    case kCC12:
      return new ChaCha20Poly1305Decrypter();
    case kCC20:
      return new ChaCha20Poly1305Rfc7539Decrypter();
    case kNULL:
      return new NullDecrypter();
    default:
      LOG(FATAL) << "Unsupported algorithm: " << algorithm;
      return nullptr;
  }
}

}  // namespace net
