// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/p256_key_exchange.h"

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

#include "base/logging.h"

using base::StringPiece;
using std::string;

namespace net {

P256KeyExchange::P256KeyExchange(EC_KEY* private_key, const uint8_t* public_key)
    : private_key_(private_key) {
  memcpy(public_key_, public_key, sizeof(public_key_));
}

P256KeyExchange::~P256KeyExchange() {}

// static
P256KeyExchange* P256KeyExchange::New(StringPiece key) {
  if (key.empty()) {
    DVLOG(1) << "Private key is empty";
    return nullptr;
  }

  const uint8_t* keyp = reinterpret_cast<const uint8_t*>(key.data());
  crypto::ScopedEC_KEY private_key(
      d2i_ECPrivateKey(nullptr, &keyp, key.size()));
  if (!private_key.get() || !EC_KEY_check_key(private_key.get())) {
    DVLOG(1) << "Private key is invalid.";
    return nullptr;
  }

  uint8_t public_key[kUncompressedP256PointBytes];
  if (EC_POINT_point2oct(EC_KEY_get0_group(private_key.get()),
                         EC_KEY_get0_public_key(private_key.get()),
                         POINT_CONVERSION_UNCOMPRESSED, public_key,
                         sizeof(public_key), nullptr) != sizeof(public_key)) {
    DVLOG(1) << "Can't get public key.";
    return nullptr;
  }

  return new P256KeyExchange(private_key.release(), public_key);
}

// static
string P256KeyExchange::NewPrivateKey() {
  crypto::ScopedEC_KEY key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (!key.get() || !EC_KEY_generate_key(key.get())) {
    DVLOG(1) << "Can't generate a new private key.";
    return string();
  }

  int key_len = i2d_ECPrivateKey(key.get(), nullptr);
  if (key_len <= 0) {
    DVLOG(1) << "Can't convert private key to string";
    return string();
  }
  scoped_ptr<uint8_t[]> private_key(new uint8_t[key_len]);
  uint8_t* keyp = private_key.get();
  if (!i2d_ECPrivateKey(key.get(), &keyp)) {
    DVLOG(1) << "Can't convert private key to string.";
    return string();
  }
  return string(reinterpret_cast<char*>(private_key.get()), key_len);
}

KeyExchange* P256KeyExchange::NewKeyPair(QuicRandom* /*rand*/) const {
  // TODO(agl): avoid the serialisation/deserialisation in this function.
  const string private_value = NewPrivateKey();
  return P256KeyExchange::New(private_value);
}

bool P256KeyExchange::CalculateSharedKey(const StringPiece& peer_public_value,
                                         string* out_result) const {
  if (peer_public_value.size() != kUncompressedP256PointBytes) {
    DVLOG(1) << "Peer public value is invalid";
    return false;
  }

  crypto::ScopedEC_POINT point(
      EC_POINT_new(EC_KEY_get0_group(private_key_.get())));
  if (!point ||
      !EC_POINT_oct2point(/* also test if point is on curve */
                          EC_KEY_get0_group(private_key_.get()), point.get(),
                          reinterpret_cast<const uint8_t*>(
                              peer_public_value.data()),
                          peer_public_value.size(), nullptr)) {
    DVLOG(1) << "Can't convert peer public value to curve point.";
    return false;
  }

  uint8_t result[kP256FieldBytes];
  if (ECDH_compute_key(result, sizeof(result), point.get(), private_key_.get(),
                       nullptr) != sizeof(result)) {
    DVLOG(1) << "Can't compute ECDH shared key.";
    return false;
  }

  out_result->assign(reinterpret_cast<char*>(result), sizeof(result));
  return true;
}

StringPiece P256KeyExchange::public_value() const {
  return StringPiece(reinterpret_cast<const char*>(public_key_),
                     sizeof(public_key_));
}

QuicTag P256KeyExchange::tag() const {
  return kP256;
}

}  // namespace net
