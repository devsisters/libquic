// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A convenience class to store rtt samples and calculate smoothed rtt.

#ifndef NET_QUIC_CONGESTION_CONTROL_RTT_STATS_H_
#define NET_QUIC_CONGESTION_CONTROL_RTT_STATS_H_

#include <stdint.h>

#include <algorithm>

#include "base/macros.h"
#include "net/quic/congestion_control/windowed_filter.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

namespace test {
class RttStatsPeer;
}  // namespace test

class NET_EXPORT_PRIVATE RttStats {
 public:
  RttStats();

  // Updates the RTT from an incoming ack which is received |send_delta| after
  // the packet is sent and the peer reports the ack being delayed |ack_delay|.
  void UpdateRtt(QuicTime::Delta send_delta,
                 QuicTime::Delta ack_delay,
                 QuicTime now);

  // Causes the smoothed_rtt to be increased to the latest_rtt if the latest_rtt
  // is larger. The mean deviation is increased to the most recent deviation if
  // it's larger.
  void ExpireSmoothedMetrics();

  // Forces RttStats to sample a new windowed min rtt within the next
  // |num_samples| UpdateRtt calls.
  void SampleNewWindowedMinRtt(uint32_t num_samples);

  // Called when connection migrates and rtt measurement needs to be reset.
  void OnConnectionMigration();

  // Returns the EWMA smoothed RTT for the connection.
  // May return Zero if no valid updates have occurred.
  QuicTime::Delta smoothed_rtt() const { return smoothed_rtt_; }

  // Returns the EWMA smoothed RTT prior to the most recent RTT sample.
  QuicTime::Delta previous_srtt() const { return previous_srtt_; }

  int64_t initial_rtt_us() const { return initial_rtt_us_; }

  // Sets an initial RTT to be used for SmoothedRtt before any RTT updates.
  void set_initial_rtt_us(int64_t initial_rtt_us) {
    if (initial_rtt_us <= 0) {
      QUIC_BUG << "Attempt to set initial rtt to <= 0.";
      return;
    }
    initial_rtt_us_ = initial_rtt_us;
  }

  // The most recent rtt measurement.
  // May return Zero if no valid updates have occurred.
  QuicTime::Delta latest_rtt() const { return latest_rtt_; }

  // Returns the min_rtt for the entire connection.
  // May return Zero if no valid updates have occurred.
  QuicTime::Delta min_rtt() const { return min_rtt_; }

  QuicTime::Delta mean_deviation() const { return mean_deviation_; }

  QuicTime::Delta WindowedMinRtt() { return windowed_min_rtt_.GetBest(); }

 private:
  friend class test::RttStatsPeer;

  // Updates the windowed min rtt. Also forces a new windowed_min_rtt sample,
  // if set by a call to SampleNewWindowedMinRtt() above.
  void UpdateWindowedMinRtt(QuicTime::Delta rtt_sample, QuicTime now);

  QuicTime::Delta latest_rtt_;
  QuicTime::Delta min_rtt_;
  QuicTime::Delta smoothed_rtt_;
  QuicTime::Delta previous_srtt_;
  // Mean RTT deviation during this session.
  // Approximation of standard deviation, the error is roughly 1.25 times
  // larger than the standard deviation, for a normally distributed signal.
  QuicTime::Delta mean_deviation_;
  int64_t initial_rtt_us_;

  // Variables used to force a new windowed_min_rtt measurement within
  // num_samples_for_forced_min_.
  QuicTime::Delta forced_windowed_min_rtt_;
  QuicTime forced_windowed_min_rtt_time_;
  uint32_t num_samples_for_forced_min_;

  // Windowed min_rtt.
  WindowedFilter<QuicTime::Delta, MinFilter<QuicTime::Delta>> windowed_min_rtt_;

  DISALLOW_COPY_AND_ASSIGN(RttStats);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_RTT_STATS_H_
