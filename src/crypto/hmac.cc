// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/hmac.h"

#include <boringssl/hmac.h>
#include <stddef.h>

#include <algorithm>

#include "base/logging.h"
#include "base/stl_util.h"
#include "crypto/openssl_util.h"
#include "crypto/secure_util.h"
#include "crypto/symmetric_key.h"

namespace crypto {

CryptoHMAC::CryptoHMAC(HashAlgorithm hash_alg) : hash_alg_(hash_alg), initialized_(false) {
  // Only SHA-1 and SHA-256 hash algorithms are supported now.
  DCHECK(hash_alg_ == CryptoSHA1 || hash_alg_ == CryptoSHA256);
}

CryptoHMAC::~CryptoHMAC() {
  // Zero out key copy.
  key_.assign(key_.size(), 0);
  STLClearObject(&key_);
}

size_t CryptoHMAC::DigestLength() const {
  switch (hash_alg_) {
    case CryptoSHA1:
      return 20;
    case CryptoSHA256:
      return 32;
    default:
      NOTREACHED();
      return 0;
  }
}

bool CryptoHMAC::Init(const unsigned char* key, size_t key_length) {
  // Init must not be called more than once on the same HMAC object.
  DCHECK(!initialized_);
  initialized_ = true;
  key_.assign(key, key + key_length);
  return true;
}

bool CryptoHMAC::Init(SymmetricKey* key) {
  std::string raw_key;
  bool result = key->GetRawKey(&raw_key) && Init(raw_key);
  // Zero out key copy.  This might get optimized away, but one can hope.
  // Using std::string to store key info at all is a larger problem.
  std::fill(raw_key.begin(), raw_key.end(), 0);
  return result;
}

bool CryptoHMAC::Sign(const base::StringPiece& data,
                unsigned char* digest,
                size_t digest_length) const {
  DCHECK(initialized_);

  ScopedOpenSSLSafeSizeBuffer<EVP_MAX_MD_SIZE> result(digest, digest_length);
  return !!::HMAC(hash_alg_ == CryptoSHA1 ? EVP_sha1() : EVP_sha256(), key_.data(),
                  key_.size(),
                  reinterpret_cast<const unsigned char*>(data.data()),
                  data.size(), result.safe_buffer(), nullptr);
}

bool CryptoHMAC::Verify(const base::StringPiece& data,
                  const base::StringPiece& digest) const {
  if (digest.size() != DigestLength())
    return false;
  return VerifyTruncated(data, digest);
}

bool CryptoHMAC::VerifyTruncated(const base::StringPiece& data,
                           const base::StringPiece& digest) const {
  if (digest.empty())
    return false;
  size_t digest_length = DigestLength();
  std::unique_ptr<unsigned char[]> computed_digest(
      new unsigned char[digest_length]);
  if (!Sign(data, computed_digest.get(), digest_length))
    return false;

  return SecureMemEqual(digest.data(), computed_digest.get(),
                        std::min(digest.size(), digest_length));
}

}  // namespace crypto
