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

  // Forces RttStats to sample a new recent min rtt within the next
  // |num_samples| UpdateRtt calls.
  void SampleNewRecentMinRtt(uint32_t num_samples);

  // Called when connection migrates and rtt measurement needs to be reset.
  void OnConnectionMigration();

  // Returns the EWMA smoothed RTT for the connection.
  // May return Zero if no valid updates have occurred.
  QuicTime::Delta smoothed_rtt() const { return smoothed_rtt_; }

  int64_t initial_rtt_us() const { return initial_rtt_us_; }

  // Sets an initial RTT to be used for SmoothedRtt before any RTT updates.
  void set_initial_rtt_us(int64_t initial_rtt_us) {
    if (initial_rtt_us <= 0) {
      LOG(DFATAL) << "Attempt to set initial rtt to <= 0.";
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

  // Returns the min_rtt since SampleNewRecentMinRtt has been called, or the
  // min_rtt for the entire connection if SampleNewMinRtt was never called.
  QuicTime::Delta recent_min_rtt() const { return recent_min_rtt_.rtt; }

  QuicTime::Delta mean_deviation() const { return mean_deviation_; }

  // Sets how old a recent min rtt sample can be.
  void set_recent_min_rtt_window(QuicTime::Delta recent_min_rtt_window) {
    recent_min_rtt_window_ = recent_min_rtt_window;
  }

 private:
  friend class test::RttStatsPeer;

  // Used to track a sampled RTT window.
  struct RttSample {
    RttSample() : rtt(QuicTime::Delta::Zero()), time(QuicTime::Zero()) {}
    RttSample(QuicTime::Delta rtt, QuicTime time) : rtt(rtt), time(time) {}

    QuicTime::Delta rtt;
    QuicTime time;  // Time the rtt sample was recorded.
  };

  // Implements the resampling algorithm and the windowed min rtt algorithm.
  void UpdateRecentMinRtt(QuicTime::Delta rtt_sample, QuicTime now);

  QuicTime::Delta latest_rtt_;
  QuicTime::Delta min_rtt_;
  QuicTime::Delta smoothed_rtt_;
  // Mean RTT deviation during this session.
  // Approximation of standard deviation, the error is roughly 1.25 times
  // larger than the standard deviation, for a normally distributed signal.
  QuicTime::Delta mean_deviation_;
  int64_t initial_rtt_us_;

  RttSample new_min_rtt_;
  uint32_t num_min_rtt_samples_remaining_;

  // State variables for Kathleen Nichols MinRTT algorithm.
  QuicTime::Delta recent_min_rtt_window_;
  RttSample recent_min_rtt_;      // a in the windowed algorithm.
  RttSample half_window_rtt_;     // b in the sampled algorithm.
  RttSample quarter_window_rtt_;  // c in the sampled algorithm.

  DISALLOW_COPY_AND_ASSIGN(RttStats);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_RTT_STATS_H_
