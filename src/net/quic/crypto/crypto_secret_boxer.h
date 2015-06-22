// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_CRYPTO_SECRET_BOXER_H_
#define NET_QUIC_CRYPTO_CRYPTO_SECRET_BOXER_H_

#include <string>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {

class QuicRandom;

// CryptoSecretBoxer encrypts small chunks of plaintext (called 'boxing') and
// then, later, can authenticate+decrypt the resulting boxes. This object is
// thread-safe.
class NET_EXPORT_PRIVATE CryptoSecretBoxer {
 public:
  CryptoSecretBoxer() {}

  // GetKeySize returns the number of bytes in a key.
  static size_t GetKeySize();

  // SetKey sets the key for this object. This must be done before |Box| or
  // |Unbox| are called. |key| must be |GetKeySize()| bytes long.
  void SetKey(base::StringPiece key);

  // Box encrypts |plaintext| using a random nonce generated from |rand| and
  // returns the resulting ciphertext. Since an authenticator and nonce are
  // included, the result will be slightly larger than |plaintext|.
  std::string Box(QuicRandom* rand, base::StringPiece plaintext) const;

  // Unbox takes the result of a previous call to |Box| in |ciphertext| and
  // authenticates+decrypts it. If |ciphertext| is not authentic then it
  // returns false. Otherwise, |out_storage| is used to store the result and
  // |out| is set to point into |out_storage| and contains the original
  // plaintext.
  bool Unbox(base::StringPiece ciphertext,
             std::string* out_storage,
             base::StringPiece* out) const;

 private:
  std::string key_;

  DISALLOW_COPY_AND_ASSIGN(CryptoSecretBoxer);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_CRYPTO_SECRET_BOXER_H_
