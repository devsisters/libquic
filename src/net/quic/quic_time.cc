// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_time.h"

#include <stdint.h>

#include "base/logging.h"

namespace net {

uint64 QuicWallTime::ToUNIXSeconds() const {
  return microseconds_ / 1000000;
}

uint64 QuicWallTime::ToUNIXMicroseconds() const {
  return microseconds_;
}

bool QuicWallTime::IsAfter(QuicWallTime other) const {
  return microseconds_ > other.microseconds_;
}

bool QuicWallTime::IsBefore(QuicWallTime other) const {
  return microseconds_ < other.microseconds_;
}

bool QuicWallTime::IsZero() const {
  return microseconds_ == 0;
}

QuicTime::Delta QuicWallTime::AbsoluteDifference(QuicWallTime other) const {
  uint64 d;

  if (microseconds_ > other.microseconds_) {
    d = microseconds_ - other.microseconds_;
  } else {
    d = other.microseconds_ - microseconds_;
  }

  if (d > static_cast<uint64>(kint64max)) {
    d = kint64max;
  }
  return QuicTime::Delta::FromMicroseconds(d);
}

QuicWallTime QuicWallTime::Add(QuicTime::Delta delta) const {
  uint64 microseconds = microseconds_ + delta.ToMicroseconds();
  if (microseconds < microseconds_) {
    microseconds = kuint64max;
  }
  return QuicWallTime(microseconds);
}

// TODO(ianswett) Test this.
QuicWallTime QuicWallTime::Subtract(QuicTime::Delta delta) const {
  uint64 microseconds = microseconds_ - delta.ToMicroseconds();
  if (microseconds > microseconds_) {
    microseconds = 0;
  }
  return QuicWallTime(microseconds);
}

}  // namespace net
