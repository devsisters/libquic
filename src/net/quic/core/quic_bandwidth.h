// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// QuicBandwidth represents a bandwidth, stored in bits per second resolution.

#ifndef NET_QUIC_QUIC_BANDWIDTH_H_
#define NET_QUIC_QUIC_BANDWIDTH_H_

#include <stdint.h>

#include <cmath>
#include <ostream>

#include "base/compiler_specific.h"
#include "net/quic/core/quic_time.h"

namespace net {

typedef uint64_t QuicByteCount;
typedef uint64_t QuicPacketCount;

class NET_EXPORT_PRIVATE QuicBandwidth {
 public:
  // Creates a new QuicBandwidth with an internal value of 0.
  static QuicBandwidth Zero();

  // Creates a new QuicBandwidth with an internal value of INT64_MAX.
  static QuicBandwidth Infinite();

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

  QuicTime::Delta TransferTime(QuicByteCount bytes) const;

  std::string ToDebugValue() const;

 private:
  explicit QuicBandwidth(int64_t bits_per_second);
  int64_t bits_per_second_;

  friend QuicBandwidth operator+(QuicBandwidth lhs, QuicBandwidth rhs);
  friend QuicBandwidth operator-(QuicBandwidth lhs, QuicBandwidth rhs);
  friend QuicBandwidth operator*(QuicBandwidth lhs, float factor);
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

// Non-member arithmetic operators for QuicBandwidth.
inline QuicBandwidth operator+(QuicBandwidth lhs, QuicBandwidth rhs) {
  return QuicBandwidth(lhs.bits_per_second_ + rhs.bits_per_second_);
}
inline QuicBandwidth operator-(QuicBandwidth lhs, QuicBandwidth rhs) {
  return QuicBandwidth(lhs.bits_per_second_ - rhs.bits_per_second_);
}
inline QuicBandwidth operator*(QuicBandwidth lhs, float rhs) {
  return QuicBandwidth(
      static_cast<int64_t>(std::llround(lhs.bits_per_second_ * rhs)));
}
inline QuicBandwidth operator*(float lhs, QuicBandwidth rhs) {
  return rhs * lhs;
}
inline QuicByteCount operator*(QuicBandwidth lhs, QuicTime::Delta rhs) {
  return lhs.ToBytesPerPeriod(rhs);
}
inline QuicByteCount operator*(QuicTime::Delta lhs, QuicBandwidth rhs) {
  return rhs * lhs;
}

// Override stream output operator for gtest.
inline std::ostream& operator<<(std::ostream& output,
                                const QuicBandwidth bandwidth) {
  output << bandwidth.ToDebugValue();
  return output;
}

}  // namespace net
#endif  // NET_QUIC_QUIC_BANDWIDTH_H_
