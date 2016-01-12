// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/curve25519.h"

#include <openssl/curve25519.h>
#include <stdint.h>

namespace crypto {

namespace curve25519 {

bool ScalarMult(const uint8_t* private_key,
                const uint8_t* peer_public_key,
                uint8_t* shared_key) {
  return !!X25519(shared_key, private_key, peer_public_key);
}

void ScalarBaseMult(const uint8_t* private_key, uint8_t* public_key) {
  X25519_public_from_private(public_key, private_key);
}

}  // namespace curve25519

}  // namespace crypto
