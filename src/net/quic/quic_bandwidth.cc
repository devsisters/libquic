// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_bandwidth.h"

#include "base/logging.h"
#include "base/time/time.h"

namespace net {

// Highest number that QuicBandwidth can hold.
const int64 kQuicInfiniteBandwidth = GG_INT64_C(0x7fffffffffffffff);

// static
QuicBandwidth QuicBandwidth::Zero() {
  return QuicBandwidth(0);
}

// static
QuicBandwidth QuicBandwidth::FromBitsPerSecond(int64 bits_per_second) {
  return QuicBandwidth(bits_per_second);
}

// static
QuicBandwidth QuicBandwidth::FromKBitsPerSecond(int64 k_bits_per_second) {
  DCHECK(k_bits_per_second < kQuicInfiniteBandwidth / 1000);
  return QuicBandwidth(k_bits_per_second * 1000);
}

// static
QuicBandwidth QuicBandwidth::FromBytesPerSecond(int64 bytes_per_second) {
  DCHECK(bytes_per_second < kQuicInfiniteBandwidth / 8);
  return QuicBandwidth(bytes_per_second * 8);
}

// static
QuicBandwidth QuicBandwidth::FromKBytesPerSecond(int64 k_bytes_per_second) {
  DCHECK(k_bytes_per_second < kQuicInfiniteBandwidth / 8000);
  return QuicBandwidth(k_bytes_per_second * 8000);
}

// static
QuicBandwidth QuicBandwidth::FromBytesAndTimeDelta(QuicByteCount bytes,
                                                   QuicTime::Delta delta) {
  DCHECK_LT(bytes,
            static_cast<uint64>(kQuicInfiniteBandwidth /
                                (8 * base::Time::kMicrosecondsPerSecond)));
  int64 bytes_per_second = (bytes * base::Time::kMicrosecondsPerSecond) /
      delta.ToMicroseconds();
  return QuicBandwidth(bytes_per_second * 8);
}

QuicBandwidth::QuicBandwidth(int64 bits_per_second)
    : bits_per_second_(bits_per_second) {
  DCHECK_GE(bits_per_second, 0);
}

int64 QuicBandwidth::ToBitsPerSecond() const {
  return bits_per_second_;
}

int64 QuicBandwidth::ToKBitsPerSecond() const {
  return bits_per_second_ / 1000;
}

int64 QuicBandwidth::ToBytesPerSecond() const {
  return bits_per_second_ / 8;
}

int64 QuicBandwidth::ToKBytesPerSecond() const {
  return bits_per_second_ / 8000;
}

QuicByteCount QuicBandwidth::ToBytesPerPeriod(
    QuicTime::Delta time_period) const {
  return ToBytesPerSecond() * time_period.ToMicroseconds() /
      base::Time::kMicrosecondsPerSecond;
}

int64 QuicBandwidth::ToKBytesPerPeriod(QuicTime::Delta time_period) const {
  return ToKBytesPerSecond() * time_period.ToMicroseconds() /
      base::Time::kMicrosecondsPerSecond;
}

bool QuicBandwidth::IsZero() const {
  return (bits_per_second_ == 0);
}

QuicBandwidth QuicBandwidth::Add(const QuicBandwidth& delta) const {
  return QuicBandwidth(bits_per_second_ + delta.bits_per_second_);
}

QuicBandwidth QuicBandwidth::Subtract(const QuicBandwidth& delta) const {
  return QuicBandwidth(bits_per_second_ - delta.bits_per_second_);
}

QuicBandwidth QuicBandwidth::Scale(float scale_factor) const {
  return QuicBandwidth(static_cast<int64>(bits_per_second_ * scale_factor));
}

QuicTime::Delta QuicBandwidth::TransferTime(QuicByteCount bytes) const {
  if (bits_per_second_ == 0) {
    return QuicTime::Delta::Zero();
  }
  return QuicTime::Delta::FromMicroseconds(
      bytes * 8 * base::Time::kMicrosecondsPerSecond / bits_per_second_);
}

}  // namespace net
