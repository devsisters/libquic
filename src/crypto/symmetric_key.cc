// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/symmetric_key.h"

#include <boringssl/evp.h>
#include <boringssl/rand.h>
#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <utility>

#include "base/logging.h"
#include "base/strings/string_util.h"
#include "crypto/openssl_util.h"

namespace crypto {

SymmetricKey::~SymmetricKey() {
  std::fill(key_.begin(), key_.end(), '\0');  // Zero out the confidential key.
}

// static
std::unique_ptr<SymmetricKey> SymmetricKey::GenerateRandomKey(
    Algorithm algorithm,
    size_t key_size_in_bits) {
  DCHECK_EQ(AES, algorithm);

  // Whitelist supported key sizes to avoid accidentaly relying on
  // algorithms available in NSS but not BoringSSL and vice
  // versa. Note that BoringSSL does not support AES-192.
  if (key_size_in_bits != 128 && key_size_in_bits != 256)
    return nullptr;

  size_t key_size_in_bytes = key_size_in_bits / 8;
  DCHECK_EQ(key_size_in_bits, key_size_in_bytes * 8);

  if (key_size_in_bytes == 0)
    return nullptr;

  OpenSSLErrStackTracer err_tracer(FROM_HERE);
  std::unique_ptr<SymmetricKey> key(new SymmetricKey);
  uint8_t* key_data = reinterpret_cast<uint8_t*>(
      base::WriteInto(&key->key_, key_size_in_bytes + 1));

  int rv = RAND_bytes(key_data, static_cast<int>(key_size_in_bytes));
  return rv == 1 ? std::move(key) : nullptr;
}

// static
std::unique_ptr<SymmetricKey> SymmetricKey::DeriveKeyFromPassword(
    Algorithm algorithm,
    const std::string& password,
    const std::string& salt,
    size_t iterations,
    size_t key_size_in_bits) {
  DCHECK(algorithm == AES || algorithm == HMAC_SHA1);

  if (algorithm == AES) {
    // Whitelist supported key sizes to avoid accidentaly relying on
    // algorithms available in NSS but not BoringSSL and vice
    // versa. Note that BoringSSL does not support AES-192.
    if (key_size_in_bits != 128 && key_size_in_bits != 256)
      return nullptr;
  }

  size_t key_size_in_bytes = key_size_in_bits / 8;
  DCHECK_EQ(key_size_in_bits, key_size_in_bytes * 8);

  if (key_size_in_bytes == 0)
    return nullptr;

  OpenSSLErrStackTracer err_tracer(FROM_HERE);
  std::unique_ptr<SymmetricKey> key(new SymmetricKey);
  uint8_t* key_data = reinterpret_cast<uint8_t*>(
      base::WriteInto(&key->key_, key_size_in_bytes + 1));
  int rv = PKCS5_PBKDF2_HMAC_SHA1(
      password.data(), password.length(),
      reinterpret_cast<const uint8_t*>(salt.data()), salt.length(),
      static_cast<unsigned>(iterations),
      key_size_in_bytes, key_data);
  return rv == 1 ? std::move(key) : nullptr;
}

// static
std::unique_ptr<SymmetricKey> SymmetricKey::Import(Algorithm algorithm,
                                                   const std::string& raw_key) {
  if (algorithm == AES) {
    // Whitelist supported key sizes to avoid accidentaly relying on
    // algorithms available in NSS but not BoringSSL and vice
    // versa. Note that BoringSSL does not support AES-192.
    if (raw_key.size() != 128/8 && raw_key.size() != 256/8)
      return nullptr;
  }

  std::unique_ptr<SymmetricKey> key(new SymmetricKey);
  key->key_ = raw_key;
  return key;
}

bool SymmetricKey::GetRawKey(std::string* raw_key) {
  *raw_key = key_;
  return true;
}

SymmetricKey::SymmetricKey() = default;

}  // namespace crypto
