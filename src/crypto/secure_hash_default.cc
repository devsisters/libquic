// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/secure_hash.h"

#include <stddef.h>

#include "base/logging.h"
#include "base/pickle.h"
#include "crypto/third_party/nss/chromium-blapi.h"
#include "crypto/third_party/nss/chromium-sha256.h"

namespace crypto {

namespace {

class SecureHashSHA256NSS : public SecureHash {
 public:
  SecureHashSHA256NSS() {
    SHA256_Begin(&ctx_);
  }

  SecureHashSHA256NSS(const SecureHashSHA256NSS& other) {
    SHA256_Clone(&ctx_, const_cast<SHA256Context*>(&other.ctx_));
  }

  ~SecureHashSHA256NSS() override { memset(&ctx_, 0, sizeof(ctx_)); }

  // SecureHash implementation:
  void Update(const void* input, size_t len) override {
    SHA256_Update(&ctx_, static_cast<const unsigned char*>(input), len);
  }

  void Finish(void* output, size_t len) override {
    SHA256_End(&ctx_, static_cast<unsigned char*>(output), NULL,
               static_cast<unsigned int>(len));
  }

  SecureHash* Clone() const override { return new SecureHashSHA256NSS(*this); }

  size_t GetHashLength() const override { return SHA256_LENGTH; }

 private:
  SHA256Context ctx_;
};

}  // namespace

SecureHash* SecureHash::Create(Algorithm algorithm) {
  switch (algorithm) {
    case SHA256:
      return new SecureHashSHA256NSS();
    default:
      NOTIMPLEMENTED();
      return NULL;
  }
}

}  // namespace crypto
