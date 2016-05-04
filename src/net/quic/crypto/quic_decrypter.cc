// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/quic_decrypter.h"

#include "crypto/hkdf.h"
#include "net/quic/crypto/aes_128_gcm_12_decrypter.h"
#include "net/quic/crypto/chacha20_poly1305_decrypter.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/null_decrypter.h"

using base::StringPiece;
using std::string;

namespace net {

// static
QuicDecrypter* QuicDecrypter::Create(QuicTag algorithm) {
  switch (algorithm) {
    case kAESG:
      return new Aes128Gcm12Decrypter();
    case kCC20:
      return new ChaCha20Poly1305Decrypter();
    case kNULL:
      return new NullDecrypter();
    default:
      LOG(FATAL) << "Unsupported algorithm: " << algorithm;
      return nullptr;
  }
}

// static
void QuicDecrypter::DiversifyPreliminaryKey(StringPiece preliminary_key,
                                            StringPiece nonce_prefix,
                                            DiversificationNonce nonce,
                                            size_t key_size,
                                            size_t nonce_prefix_size,
                                            string* out_key,
                                            string* out_nonce_prefix) {
  crypto::HKDF hkdf(preliminary_key.as_string() + nonce_prefix.as_string(),
                    StringPiece(nonce, kDiversificationNonceSize),
                    "QUIC key diversification", 0, key_size, 0,
                    nonce_prefix_size, 0);
  *out_key = hkdf.server_write_key().as_string();
  *out_nonce_prefix = hkdf.server_write_iv().as_string();
}

}  // namespace net
