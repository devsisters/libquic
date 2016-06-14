// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#ifndef NET_QUIC_CONGESTION_CONTROL_WINDOWED_FILTER_H_
#define NET_QUIC_CONGESTION_CONTROL_WINDOWED_FILTER_H_

// Implements Kathleen Nichols' algorithm for tracking the minimum (or maximum)
// estimate of a stream of samples over some fixed time interval. (E.g.,
// the minimum RTT over the past five minutes.) The algorithm keeps track of
// the best, second best, and third best min (or max) estimates, maintaining an
// invariant that the measurement time of the n'th best >= n-1'th best.

// The algorithm works as follows. On a reset, all three estimates are set to
// the same sample. The second best estimate is then recorded in the second
// quarter of the window, and a third best estimate is recorded in the second
// half of the window, bounding the worst case error when the true min is
// monotonically increasing (or true max is monotonically decreasing) over the
// window.
//
// A new best sample replaces all three estimates, since the new best is lower
// (or higher) than everything else in the window and it is the most recent.
// The window thus effectively gets reset on every new min. The same property
// holds true for second best and third best estimates. Specifically, when a
// sample arrives that is better than the second best but not better than the
// best, it replaces the second and third best estimates but not the best
// estimate. Similarly, a sample that is better than the third best estimate
// but not the other estimates replaces only the third best estimate.
//
// Finally, when the best expires, it is replaced by the second best, which in
// turn is replaced by the third best. The newest sample replaces the third
// best.

#include "base/logging.h"
#include "net/quic/quic_time.h"

namespace net {

// Compares two values and returns true if the first is less than or equal
// to the second.
template <class T>
struct MinFilter {
  bool operator()(const T& lhs, const T& rhs) const { return lhs <= rhs; }
};

// Compares two values and returns true if the first is greater than or equal
// to the second.
template <class T>
struct MaxFilter {
  bool operator()(const T& lhs, const T& rhs) const { return lhs >= rhs; }
};

// Use the following to construct a windowed filter object of type T.
// For a min filter: WindowedFilter<T, MinFilter<T>> ObjectName;
// For a max filter: WindowedFilter<T, MaxFilter<T>> ObjectName;
template <class T, class Compare>
class WindowedFilter {
 public:
  // |window_length| is the period after which a best estimate expires.
  // |zero_value| is used as the uninitialized value for objects of T.
  // Importantly, |zero_value| should be an invalid value for a true sample.
  WindowedFilter(QuicTime::Delta window_length, T zero_value)
      : window_length_(window_length),
        zero_value_(zero_value),
        estimates_{Sample(zero_value_, QuicTime::Zero()),
                   Sample(zero_value_, QuicTime::Zero()),
                   Sample(zero_value_, QuicTime::Zero())} {}

  // Updates best estimates with |sample|, and expires and updates best
  // estimates as necessary.
  void Update(T new_sample, QuicTime new_time) {
    // Reset all estimates if they have not yet been initialized, if new sample
    // is a new best, or if the newest recorded estimate is too old.
    if (estimates_[0].sample == zero_value_ ||
        Compare()(new_sample, estimates_[0].sample) ||
        new_time.Subtract(estimates_[2].time) > window_length_) {
      Reset(new_sample, new_time);
      return;
    }

    if (Compare()(new_sample, estimates_[1].sample)) {
      estimates_[1] = Sample(new_sample, new_time);
      estimates_[2] = estimates_[1];
    } else if (Compare()(new_sample, estimates_[2].sample)) {
      estimates_[2] = Sample(new_sample, new_time);
    }

    // Expire and update estimates as necessary.
    if (new_time.Subtract(estimates_[0].time) > window_length_) {
      // The best estimate hasn't been updated for an entire window, so promote
      // second and third best estimates.
      estimates_[0] = estimates_[1];
      estimates_[1] = estimates_[2];
      estimates_[2] = Sample(new_sample, new_time);
      // Need to iterate one more time. Check if the new best estimate is
      // outside the window as well, since it may also have been recorded a
      // long time ago. Don't need to iterate once more since we cover that
      // case at the beginning of the method.
      if (new_time.Subtract(estimates_[0].time) > window_length_) {
        estimates_[0] = estimates_[1];
        estimates_[1] = estimates_[2];
      }
      return;
    }
    if (estimates_[1].sample == estimates_[0].sample &&
        new_time.Subtract(estimates_[1].time) > window_length_ >> 2) {
      // A quarter of the window has passed without a better sample, so the
      // second-best estimate is taken from the second quarter of the window.
      estimates_[2] = estimates_[1] = Sample(new_sample, new_time);
      return;
    }

    if (estimates_[2].sample == estimates_[1].sample &&
        new_time.Subtract(estimates_[2].time) > window_length_ >> 1) {
      // We've passed a half of the window without a better estimate, so take
      // a third-best estimate from the second half of the window.
      estimates_[2] = Sample(new_sample, new_time);
    }
  }

  // Resets all estimates to new sample.
  void Reset(T new_sample, QuicTime new_time) {
    estimates_[0] = estimates_[1] = estimates_[2] =
        Sample(new_sample, new_time);
  }

  T GetBest() const { return estimates_[0].sample; }
  T GetSecondBest() const { return estimates_[1].sample; }
  T GetThirdBest() const { return estimates_[2].sample; }

 private:
  struct Sample {
    T sample;
    QuicTime time;
    Sample(T init_sample, QuicTime init_time)
        : sample(init_sample), time(init_time) {}
  };

  QuicTime::Delta window_length_;  // Time length of window.
  T zero_value_;                   // Uninitialized value of T.
  Sample estimates_[3];            // Best estimate is element 0.
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_WINDOWED_FILTER_H_
