// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_clock.h"

#include "base/time/time.h"

namespace net {

QuicClock::QuicClock() {
}

QuicClock::~QuicClock() {}

QuicTime QuicClock::ApproximateNow() const {
  // At the moment, Chrome does not have a distinct notion of ApproximateNow().
  // We should consider implementing this using MessageLoop::recent_time_.
  return Now();
}

QuicTime QuicClock::Now() const {
  return QuicTime(base::TimeTicks::Now());
}

QuicWallTime QuicClock::WallNow() const {
  return QuicWallTime::FromUNIXSeconds(base::Time::Now().ToTimeT());
}

}  // namespace net
