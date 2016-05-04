// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_bandwidth.h"

#include <stdint.h>

#include "base/logging.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_time.h"
#include "net/quic/quic_types.h"

namespace net {

// Highest number that QuicBandwidth can hold.
const int64_t kQuicInfiniteBandwidth = INT64_C(0x7fffffffffffffff);

// static
QuicBandwidth QuicBandwidth::Zero() {
  return QuicBandwidth(0);
}

// static
QuicBandwidth QuicBandwidth::FromBitsPerSecond(int64_t bits_per_second) {
  return QuicBandwidth(bits_per_second);
}

// static
QuicBandwidth QuicBandwidth::FromKBitsPerSecond(int64_t k_bits_per_second) {
  DCHECK(k_bits_per_second < kQuicInfiniteBandwidth / 1000);
  return QuicBandwidth(k_bits_per_second * 1000);
}

// static
QuicBandwidth QuicBandwidth::FromBytesPerSecond(int64_t bytes_per_second) {
  DCHECK(bytes_per_second < kQuicInfiniteBandwidth / 8);
  return QuicBandwidth(bytes_per_second * 8);
}

// static
QuicBandwidth QuicBandwidth::FromKBytesPerSecond(int64_t k_bytes_per_second) {
  DCHECK(k_bytes_per_second < kQuicInfiniteBandwidth / 8000);
  return QuicBandwidth(k_bytes_per_second * 8000);
}

// static
QuicBandwidth QuicBandwidth::FromBytesAndTimeDelta(QuicByteCount bytes,
                                                   QuicTime::Delta delta) {
  DCHECK_LT(bytes, static_cast<uint64_t>(kQuicInfiniteBandwidth /
                                         (8 * kNumMicrosPerSecond)));
  int64_t bytes_per_second =
      (bytes * kNumMicrosPerSecond) / delta.ToMicroseconds();
  return QuicBandwidth(bytes_per_second * 8);
}

QuicBandwidth::QuicBandwidth(int64_t bits_per_second)
    : bits_per_second_(bits_per_second) {
  if (bits_per_second < 0) {
    QUIC_BUG << "Can't set negative bandwidth " << bits_per_second;
    bits_per_second_ = 0;
    return;
  }
  bits_per_second_ = bits_per_second;
}

int64_t QuicBandwidth::ToBitsPerSecond() const {
  return bits_per_second_;
}

int64_t QuicBandwidth::ToKBitsPerSecond() const {
  return bits_per_second_ / 1000;
}

int64_t QuicBandwidth::ToBytesPerSecond() const {
  return bits_per_second_ / 8;
}

int64_t QuicBandwidth::ToKBytesPerSecond() const {
  return bits_per_second_ / 8000;
}

QuicByteCount QuicBandwidth::ToBytesPerPeriod(
    QuicTime::Delta time_period) const {
  return ToBytesPerSecond() * time_period.ToMicroseconds() /
         kNumMicrosPerSecond;
}

int64_t QuicBandwidth::ToKBytesPerPeriod(QuicTime::Delta time_period) const {
  return ToKBytesPerSecond() * time_period.ToMicroseconds() /
         kNumMicrosPerSecond;
}

bool QuicBandwidth::IsZero() const {
  return (bits_per_second_ == 0);
}

QuicBandwidth QuicBandwidth::Add(QuicBandwidth delta) const {
  return QuicBandwidth(bits_per_second_ + delta.bits_per_second_);
}

QuicBandwidth QuicBandwidth::Subtract(QuicBandwidth delta) const {
  return QuicBandwidth(bits_per_second_ - delta.bits_per_second_);
}

QuicBandwidth QuicBandwidth::Scale(float scale_factor) const {
  return QuicBandwidth(static_cast<int64_t>(bits_per_second_ * scale_factor));
}

QuicTime::Delta QuicBandwidth::TransferTime(QuicByteCount bytes) const {
  if (bits_per_second_ == 0) {
    return QuicTime::Delta::Zero();
  }
  return QuicTime::Delta::FromMicroseconds(bytes * 8 * kNumMicrosPerSecond /
                                           bits_per_second_);
}

}  // namespace net
