// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_CURVE25519_H
#define CRYPTO_CURVE25519_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/crypto_export.h"

namespace crypto {

// Curve25519 implements the elliptic curve group known as Curve25519, as
// described in "Curve 25519: new Diffie-Hellman Speed Records",
// by D.J. Bernstein. Additional information is available at
// http://cr.yp.to/ecdh.html.
//
// TODO(davidben): Once iOS is switched to BoringSSL (https://crbug.com/338886),
// remove this file altogether and switch callers to using BoringSSL's
// curve25519.h directly.
namespace curve25519 {

// kBytes is the number of bytes in the result of the Diffie-Hellman operation,
// which is an element of GF(2^255-19).
static const size_t kBytes = 32;

// kScalarBytes is the number of bytes in an element of the scalar field:
// GF(2^252 + 27742317777372353535851937790883648493).
static const size_t kScalarBytes = 32;

// ScalarMult computes the |shared_key| from |private_key| and
// |peer_public_key|. This method is a wrapper for |curve25519_donna()|. It
// calls that function with |private_key| as |secret| and |peer_public_key| as
// basepoint. |private_key| should be of length |kScalarBytes| and
// |peer_public_key| should be of length |kBytes|. It returns true on success
// and false if |peer_public_key| was invalid.
// See the "Computing shared secrets" section of http://cr.yp.to/ecdh.html.
CRYPTO_EXPORT bool ScalarMult(const uint8_t* private_key,
                              const uint8_t* peer_public_key,
                              uint8_t* shared_key);

// ScalarBaseMult computes the |public_key| from |private_key|. This method is a
// wrapper for |curve25519_donna()|. It calls that function with |private_key|
// as |secret| and |kBasePoint| as basepoint. |private_key| should be of length
// |kScalarBytes|. See "Computing public keys" section of
// http://cr.yp.to/ecdh.html.
CRYPTO_EXPORT void ScalarBaseMult(const uint8_t* private_key,
                                  uint8_t* public_key);

}  // namespace curve25519

}  // namespace crypto

#endif  // CRYPTO_CURVE25519_H
