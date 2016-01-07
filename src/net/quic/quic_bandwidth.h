// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// QuicBandwidth represents a bandwidth, stored in bits per second resolution.

#ifndef NET_QUIC_QUIC_BANDWIDTH_H_
#define NET_QUIC_QUIC_BANDWIDTH_H_

#include <stdint.h>

#include "base/compiler_specific.h"
#include "net/quic/quic_time.h"

namespace net {

typedef uint64_t QuicByteCount;
typedef uint64_t QuicPacketCount;

class NET_EXPORT_PRIVATE QuicBandwidth {
 public:
  // Creates a new QuicBandwidth with an internal value of 0.
  static QuicBandwidth Zero();

  // Create a new QuicBandwidth holding the bits per second.
  static QuicBandwidth FromBitsPerSecond(int64_t bits_per_second);

  // Create a new QuicBandwidth holding the kilo bits per second.
  static QuicBandwidth FromKBitsPerSecond(int64_t k_bits_per_second);

  // Create a new QuicBandwidth holding the bytes per second.
  static QuicBandwidth FromBytesPerSecond(int64_t bytes_per_second);

  // Create a new QuicBandwidth holding the kilo bytes per second.
  static QuicBandwidth FromKBytesPerSecond(int64_t k_bytes_per_second);

  // Create a new QuicBandwidth based on the bytes per the elapsed delta.
  static QuicBandwidth FromBytesAndTimeDelta(QuicByteCount bytes,
                                             QuicTime::Delta delta);

  int64_t ToBitsPerSecond() const;

  int64_t ToKBitsPerSecond() const;

  int64_t ToBytesPerSecond() const;

  int64_t ToKBytesPerSecond() const;

  QuicByteCount ToBytesPerPeriod(QuicTime::Delta time_period) const;

  int64_t ToKBytesPerPeriod(QuicTime::Delta time_period) const;

  bool IsZero() const;

  QuicBandwidth Add(const QuicBandwidth& delta) const WARN_UNUSED_RESULT;

  QuicBandwidth Subtract(const QuicBandwidth& delta) const WARN_UNUSED_RESULT;

  QuicBandwidth Scale(float scale_factor) const WARN_UNUSED_RESULT;

  QuicTime::Delta TransferTime(QuicByteCount bytes) const;

 private:
  explicit QuicBandwidth(int64_t bits_per_second);
  int64_t bits_per_second_;
};

// Non-member relational operators for QuicBandwidth.
inline bool operator==(QuicBandwidth lhs, QuicBandwidth rhs) {
  return lhs.ToBitsPerSecond() == rhs.ToBitsPerSecond();
}
inline bool operator!=(QuicBandwidth lhs, QuicBandwidth rhs) {
  return !(lhs == rhs);
}
inline bool operator<(QuicBandwidth lhs, QuicBandwidth rhs) {
  return lhs.ToBitsPerSecond() < rhs.ToBitsPerSecond();
}
inline bool operator>(QuicBandwidth lhs, QuicBandwidth rhs) {
  return rhs < lhs;
}
inline bool operator<=(QuicBandwidth lhs, QuicBandwidth rhs) {
  return !(rhs < lhs);
}
inline bool operator>=(QuicBandwidth lhs, QuicBandwidth rhs) {
  return !(lhs < rhs);
}

}  // namespace net
#endif  // NET_QUIC_QUIC_BANDWIDTH_H_
