// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// QuicTime represents one point in time, stored in microsecond resolution.
// QuicTime is monotonically increasing, even across system clock adjustments.
// The epoch (time 0) of QuicTime is unspecified.
//
// This implementation wraps the classes base::TimeTicks and base::TimeDelta.

#ifndef NET_QUIC_QUIC_TIME_H_
#define NET_QUIC_QUIC_TIME_H_

#include <stdint.h>

#include "base/compiler_specific.h"
#include "base/time/time.h"
#include "net/base/net_export.h"

#define QUICTIME_CONSTEXPR inline

namespace net {

static const int kNumSecondsPerMinute = 60;
static const int kNumSecondsPerHour = kNumSecondsPerMinute * 60;
static const uint64_t kNumMicrosPerSecond = base::Time::kMicrosecondsPerSecond;
static const uint64_t kNumMicrosPerMilli =
    base::Time::kMicrosecondsPerMillisecond;

// A QuicTime is a purely relative time. QuicTime values from different clocks
// cannot be compared to each other. If you need an absolute time, see
// QuicWallTime, below.
class NET_EXPORT_PRIVATE QuicTime {
 public:
  // A QuicTime::Delta represents the signed difference between two points in
  // time, stored in microsecond resolution.
  class NET_EXPORT_PRIVATE Delta {
   public:
    explicit Delta(base::TimeDelta delta);

    // Create a object with an offset of 0.
    static QUICTIME_CONSTEXPR Delta Zero() { return Delta(0); }

    // Create a object with infinite offset time.
    static QUICTIME_CONSTEXPR Delta Infinite() {
      return Delta(kQuicInfiniteTimeUs);
    }

    // Converts a number of seconds to a time offset.
    static QUICTIME_CONSTEXPR Delta FromSeconds(int64_t secs) {
      return Delta(secs * 1000 * 1000);
    }

    // Converts a number of milliseconds to a time offset.
    static QUICTIME_CONSTEXPR Delta FromMilliseconds(int64_t ms) {
      return Delta(ms * 1000);
    }

    // Converts a number of microseconds to a time offset.
    static QUICTIME_CONSTEXPR Delta FromMicroseconds(int64_t us) {
      return Delta(us);
    }

    // Converts the time offset to a rounded number of seconds.
    inline int64_t ToSeconds() const { return time_offset_ / 1000 / 1000; }

    // Converts the time offset to a rounded number of milliseconds.
    inline int64_t ToMilliseconds() const { return time_offset_ / 1000; }

    // Converts the time offset to a rounded number of microseconds.
    inline int64_t ToMicroseconds() const { return time_offset_; }

    inline Delta Add(Delta delta) const WARN_UNUSED_RESULT {
      return Delta(time_offset_ + delta.time_offset_);
    }

    inline Delta Subtract(Delta delta) const WARN_UNUSED_RESULT {
      return Delta(time_offset_ - delta.time_offset_);
    }

    inline Delta Multiply(int i) const WARN_UNUSED_RESULT {
      return Delta(time_offset_ * i);
    }

    inline Delta Multiply(double d) const WARN_UNUSED_RESULT {
      return Delta(time_offset_ * d);
    }

    // Returns the larger delta of time1 and time2.
    static inline Delta Max(Delta delta1, Delta delta2) {
      return delta1 < delta2 ? delta2 : delta1;
    }

    // Returns the smaller delta of time1 and time2.
    static inline Delta Min(Delta delta1, Delta delta2) {
      return delta1 < delta2 ? delta1 : delta2;
    }

    inline bool IsZero() const { return time_offset_ == 0; }

    inline bool IsInfinite() const {
      return time_offset_ == kQuicInfiniteTimeUs;
    }

   private:
    base::TimeDelta delta_;
    friend inline bool operator==(QuicTime::Delta lhs, QuicTime::Delta rhs);
    friend inline bool operator<(QuicTime::Delta lhs, QuicTime::Delta rhs);

    // Highest number of microseconds that DateTimeOffset can hold.
    static const int64_t kQuicInfiniteTimeUs = INT64_C(0x7fffffffffffffff) / 10;

    explicit QUICTIME_CONSTEXPR Delta(int64_t time_offset)
        : time_offset_(time_offset) {}

    int64_t time_offset_;
    friend class QuicTime;
    friend class QuicClock;
  };

  explicit QuicTime(base::TimeTicks ticks) : time_(ticks.ToInternalValue()) {}

  // Creates a new QuicTime with an internal value of 0.  IsInitialized()
  // will return false for these times.
  static QUICTIME_CONSTEXPR QuicTime Zero() { return QuicTime(0); }

  // Creates a new QuicTime with an infinite time.
  static QUICTIME_CONSTEXPR QuicTime Infinite() {
    return QuicTime(Delta::kQuicInfiniteTimeUs);
  }

  // Returns the later time of time1 and time2.
  static inline QuicTime Max(QuicTime time1, QuicTime time2) {
    return time1 < time2 ? time2 : time1;
  }

  // Produce the internal value to be used when logging.  This value
  // represents the number of microseconds since some epoch.  It may
  // be the UNIX epoch on some platforms.  On others, it may
  // be a CPU ticks based value.
  inline int64_t ToDebuggingValue() const { return time_; }

  inline bool IsInitialized() const { return 0 != time_; }

  inline QuicTime Add(Delta delta) const WARN_UNUSED_RESULT {
    return QuicTime(time_ + delta.time_offset_);
  }

  inline QuicTime Subtract(Delta delta) const WARN_UNUSED_RESULT {
    return QuicTime(time_ - delta.time_offset_);
  }

  inline Delta Subtract(QuicTime other) const WARN_UNUSED_RESULT {
    return Delta(time_ - other.time_);
  }

 private:
  friend inline bool operator==(QuicTime lhs, QuicTime rhs);
  friend inline bool operator<(QuicTime lhs, QuicTime rhs);
  friend class QuicClock;
  friend class QuicClockTest;

  explicit QUICTIME_CONSTEXPR QuicTime(int64_t time) : time_(time) {}

  int64_t time_;
};

// A QuicWallTime represents an absolute time that is globally consistent. In
// practice, clock-skew means that comparing values from different machines
// requires some flexibility in interpretation.
class NET_EXPORT_PRIVATE QuicWallTime {
 public:
  // FromUNIXSeconds constructs a QuicWallTime from a count of the seconds
  // since the UNIX epoch.
  static QUICTIME_CONSTEXPR QuicWallTime FromUNIXSeconds(uint64_t seconds) {
    return QuicWallTime(seconds * 1000000);
  }

  static QUICTIME_CONSTEXPR QuicWallTime
  FromUNIXMicroseconds(uint64_t microseconds) {
    return QuicWallTime(microseconds);
  }

  // Zero returns a QuicWallTime set to zero. IsZero will return true for this
  // value.
  static QUICTIME_CONSTEXPR QuicWallTime Zero() { return QuicWallTime(0); }

  // Returns the number of seconds since the UNIX epoch.
  uint64_t ToUNIXSeconds() const;
  // Returns the number of microseconds since the UNIX epoch.
  uint64_t ToUNIXMicroseconds() const;

  bool IsAfter(QuicWallTime other) const;
  bool IsBefore(QuicWallTime other) const;

  // IsZero returns true if this object is the result of calling |Zero|.
  bool IsZero() const;

  // AbsoluteDifference returns the absolute value of the time difference
  // between |this| and |other|.
  QuicTime::Delta AbsoluteDifference(QuicWallTime other) const;

  // Add returns a new QuicWallTime that represents the time of |this| plus
  // |delta|.
  QuicWallTime Add(QuicTime::Delta delta) const WARN_UNUSED_RESULT;

  // Subtract returns a new QuicWallTime that represents the time of |this|
  // minus |delta|.
  QuicWallTime Subtract(QuicTime::Delta delta) const WARN_UNUSED_RESULT;

 private:
  explicit QUICTIME_CONSTEXPR QuicWallTime(uint64_t microseconds)
      : microseconds_(microseconds) {}

  uint64_t microseconds_;
};

// Non-member relational operators for QuicTime::Delta.
inline bool operator==(QuicTime::Delta lhs, QuicTime::Delta rhs) {
  return lhs.time_offset_ == rhs.time_offset_;
}
inline bool operator!=(QuicTime::Delta lhs, QuicTime::Delta rhs) {
  return !(lhs == rhs);
}
inline bool operator<(QuicTime::Delta lhs, QuicTime::Delta rhs) {
  return lhs.time_offset_ < rhs.time_offset_;
}
inline bool operator>(QuicTime::Delta lhs, QuicTime::Delta rhs) {
  return rhs < lhs;
}
inline bool operator<=(QuicTime::Delta lhs, QuicTime::Delta rhs) {
  return !(rhs < lhs);
}
inline bool operator>=(QuicTime::Delta lhs, QuicTime::Delta rhs) {
  return !(lhs < rhs);
}
// Non-member relational operators for QuicTime.
inline bool operator==(QuicTime lhs, QuicTime rhs) {
  return lhs.time_ == rhs.time_;
}
inline bool operator!=(QuicTime lhs, QuicTime rhs) {
  return !(lhs == rhs);
}
inline bool operator<(QuicTime lhs, QuicTime rhs) {
  return lhs.time_ < rhs.time_;
}
inline bool operator>(QuicTime lhs, QuicTime rhs) {
  return rhs < lhs;
}
inline bool operator<=(QuicTime lhs, QuicTime rhs) {
  return !(rhs < lhs);
}
inline bool operator>=(QuicTime lhs, QuicTime rhs) {
  return !(lhs < rhs);
}

}  // namespace net

#endif  // NET_QUIC_QUIC_TIME_H_
