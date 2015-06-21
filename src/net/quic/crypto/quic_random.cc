// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/quic_random.h"

#include "base/logging.h"
#include "base/memory/singleton.h"
#include "crypto/random.h"

namespace net {

namespace {

class DefaultRandom : public QuicRandom {
 public:
  static DefaultRandom* GetInstance();

  // QuicRandom implementation
  void RandBytes(void* data, size_t len) override;
  uint64 RandUint64() override;
  void Reseed(const void* additional_entropy, size_t entropy_len) override;

 private:
  DefaultRandom() {};
  ~DefaultRandom() override {}

  friend struct DefaultSingletonTraits<DefaultRandom>;
  DISALLOW_COPY_AND_ASSIGN(DefaultRandom);
};

DefaultRandom* DefaultRandom::GetInstance() {
  return Singleton<DefaultRandom>::get();
}

void DefaultRandom::RandBytes(void* data, size_t len) {
  crypto::RandBytes(data, len);
}

uint64 DefaultRandom::RandUint64() {
  uint64 value;
  RandBytes(&value, sizeof(value));
  return value;
}

void DefaultRandom::Reseed(const void* additional_entropy, size_t entropy_len) {
  // No such function exists in crypto/random.h.
}

}  // namespace

// static
QuicRandom* QuicRandom::GetInstance() { return DefaultRandom::GetInstance(); }

}  // namespace net
