// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_QUIC_RANDOM_H_
#define NET_QUIC_CRYPTO_QUIC_RANDOM_H_

#include <stddef.h>
#include <stdint.h>

#include "net/base/net_export.h"

namespace net {

// The interface for a random number generator.
class NET_EXPORT_PRIVATE QuicRandom {
 public:
  virtual ~QuicRandom() {}

  // Returns the default random number generator, which is cryptographically
  // secure and thread-safe.
  static QuicRandom* GetInstance();

  // Generates |len| random bytes in the |data| buffer.
  virtual void RandBytes(void* data, size_t len) = 0;

  // Returns a random number in the range [0, kuint64max].
  virtual uint64_t RandUint64() = 0;

  // Reseeds the random number generator with additional entropy input.
  // NOTE: the constructor of a QuicRandom object is responsible for seeding
  // itself with enough entropy input.
  virtual void Reseed(const void* additional_entropy, size_t entropy_len) = 0;
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_QUIC_RANDOM_H_
