// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/curve25519_key_exchange.h"

#include "base/logging.h"
#include "crypto/curve25519.h"
#include "net/quic/crypto/quic_random.h"

using base::StringPiece;
using std::string;

namespace net {

Curve25519KeyExchange::Curve25519KeyExchange() {}

Curve25519KeyExchange::~Curve25519KeyExchange() {}

// static
Curve25519KeyExchange* Curve25519KeyExchange::New(
    const StringPiece& private_key) {
  Curve25519KeyExchange* ka;
  // We don't want to #include the NaCl headers in the public header file, so
  // we use literals for the sizes of private_key_ and public_key_. Here we
  // assert that those values are equal to the values from the NaCl header.
  static_assert(sizeof(ka->private_key_) == crypto::curve25519::kScalarBytes,
                "header out of sync");
  static_assert(sizeof(ka->public_key_) == crypto::curve25519::kBytes,
                "header out of sync");

  if (private_key.size() != crypto::curve25519::kScalarBytes) {
    return nullptr;
  }

  ka = new Curve25519KeyExchange();
  memcpy(ka->private_key_, private_key.data(),
         crypto::curve25519::kScalarBytes);
  crypto::curve25519::ScalarBaseMult(ka->private_key_, ka->public_key_);
  return ka;
}

// static
string Curve25519KeyExchange::NewPrivateKey(QuicRandom* rand) {
  uint8_t private_key[crypto::curve25519::kScalarBytes];
  rand->RandBytes(private_key, sizeof(private_key));

  // This makes |private_key| a valid scalar, as specified on
  // http://cr.yp.to/ecdh.html
  private_key[0] &= 248;
  private_key[31] &= 127;
  private_key[31] |= 64;
  return string(reinterpret_cast<char*>(private_key), sizeof(private_key));
}

KeyExchange* Curve25519KeyExchange::NewKeyPair(QuicRandom* rand) const {
  const string private_value = NewPrivateKey(rand);
  return Curve25519KeyExchange::New(private_value);
}

bool Curve25519KeyExchange::CalculateSharedKey(
    const StringPiece& peer_public_value,
    string* out_result) const {
  if (peer_public_value.size() != crypto::curve25519::kBytes) {
    return false;
  }

  uint8_t result[crypto::curve25519::kBytes];
  if (!crypto::curve25519::ScalarMult(
          private_key_,
          reinterpret_cast<const uint8_t*>(peer_public_value.data()), result)) {
    return false;
  }
  out_result->assign(reinterpret_cast<char*>(result), sizeof(result));

  return true;
}

StringPiece Curve25519KeyExchange::public_value() const {
  return StringPiece(reinterpret_cast<const char*>(public_key_),
                     sizeof(public_key_));
}

QuicTag Curve25519KeyExchange::tag() const {
  return kC255;
}

}  // namespace net
