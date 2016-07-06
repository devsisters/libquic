// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_CLOCK_H_
#define NET_QUIC_QUIC_CLOCK_H_

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/quic/quic_time.h"

namespace net {

typedef double WallTime;

// Clock to efficiently retrieve an approximately accurate time from an
// EpollServer.
class NET_EXPORT_PRIVATE QuicClock {
 public:
  QuicClock();
  virtual ~QuicClock();

  // Returns the approximate current time as a QuicTime object.
  virtual QuicTime ApproximateNow() const;

  // Returns the current time as a QuicTime object.
  // Note: this use significant resources please use only if needed.
  virtual QuicTime Now() const;

  // WallNow returns the current wall-time - a time that is consistent across
  // different clocks.
  virtual QuicWallTime WallNow() const;

  // Converts |walltime| to a QuicTime relative to this clock's epoch.
  virtual QuicTime ConvertWallTimeToQuicTime(
      const QuicWallTime& walltime) const;

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicClock);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CLOCK_H_
