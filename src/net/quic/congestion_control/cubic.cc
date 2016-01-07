// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/cubic.h"

#include <stdint.h>
#include <algorithm>
#include <cmath>

#include "base/logging.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

using std::max;

namespace net {

namespace {

// Constants based on TCP defaults.
// The following constants are in 2^10 fractions of a second instead of ms to
// allow a 10 shift right to divide.
const int kCubeScale = 40;  // 1024*1024^3 (first 1024 is from 0.100^3)
                            // where 0.100 is 100 ms which is the scaling
                            // round trip time.
const int kCubeCongestionWindowScale = 410;
const uint64_t kCubeFactor =
    (UINT64_C(1) << kCubeScale) / kCubeCongestionWindowScale;

const uint32_t kDefaultNumConnections = 2;
const float kBeta = 0.7f;  // Default Cubic backoff factor.
// Additional backoff factor when loss occurs in the concave part of the Cubic
// curve. This additional backoff factor is expected to give up bandwidth to
// new concurrent flows and speed up convergence.
const float kBetaLastMax = 0.85f;

}  // namespace

Cubic::Cubic(const QuicClock* clock)
    : clock_(clock),
      num_connections_(kDefaultNumConnections),
      epoch_(QuicTime::Zero()),
      app_limited_start_time_(QuicTime::Zero()),
      last_update_time_(QuicTime::Zero()) {
  Reset();
}

void Cubic::SetNumConnections(int num_connections) {
  num_connections_ = num_connections;
}

float Cubic::Alpha() const {
  // TCPFriendly alpha is described in Section 3.3 of the CUBIC paper. Note that
  // beta here is a cwnd multiplier, and is equal to 1-beta from the paper.
  // We derive the equivalent alpha for an N-connection emulation as:
  const float beta = Beta();
  return 3 * num_connections_ * num_connections_ * (1 - beta) / (1 + beta);
}

float Cubic::Beta() const {
  // kNConnectionBeta is the backoff factor after loss for our N-connection
  // emulation, which emulates the effective backoff of an ensemble of N
  // TCP-Reno connections on a single loss event. The effective multiplier is
  // computed as:
  return (num_connections_ - 1 + kBeta) / num_connections_;
}

void Cubic::Reset() {
  epoch_ = QuicTime::Zero();  // Reset time.
  app_limited_start_time_ = QuicTime::Zero();
  last_update_time_ = QuicTime::Zero();  // Reset time.
  last_congestion_window_ = 0;
  last_max_congestion_window_ = 0;
  acked_packets_count_ = 0;
  estimated_tcp_congestion_window_ = 0;
  origin_point_congestion_window_ = 0;
  time_to_origin_point_ = 0;
  last_target_congestion_window_ = 0;
}

void Cubic::OnApplicationLimited() {
  if (FLAGS_shift_quic_cubic_epoch_when_app_limited) {
    // When sender is not using the available congestion window, Cubic's epoch
    // should not continue growing. Record the time when sender goes into an
    // app-limited period here, to compensate later when cwnd growth happens.
    if (app_limited_start_time_ == QuicTime::Zero()) {
      app_limited_start_time_ = clock_->ApproximateNow();
    }
  } else {
    // When sender is not using the available congestion window, Cubic's epoch
    // should not continue growing. Reset the epoch when in such a period.
    epoch_ = QuicTime::Zero();
  }
}

QuicPacketCount Cubic::CongestionWindowAfterPacketLoss(
    QuicPacketCount current_congestion_window) {
  if (current_congestion_window < last_max_congestion_window_) {
    // We never reached the old max, so assume we are competing with another
    // flow. Use our extra back off factor to allow the other flow to go up.
    last_max_congestion_window_ =
        static_cast<int>(kBetaLastMax * current_congestion_window);
  } else {
    last_max_congestion_window_ = current_congestion_window;
  }
  epoch_ = QuicTime::Zero();  // Reset time.
  return static_cast<int>(current_congestion_window * Beta());
}

QuicPacketCount Cubic::CongestionWindowAfterAck(
    QuicPacketCount current_congestion_window,
    QuicTime::Delta delay_min) {
  acked_packets_count_ += 1;  // Packets acked.
  QuicTime current_time = clock_->ApproximateNow();

  // Cubic is "independent" of RTT, the update is limited by the time elapsed.
  if (last_congestion_window_ == current_congestion_window &&
      (current_time.Subtract(last_update_time_) <= MaxCubicTimeInterval())) {
    return max(last_target_congestion_window_,
               estimated_tcp_congestion_window_);
  }
  last_congestion_window_ = current_congestion_window;
  last_update_time_ = current_time;

  if (!epoch_.IsInitialized()) {
    // First ACK after a loss event.
    epoch_ = current_time;     // Start of epoch.
    acked_packets_count_ = 1;  // Reset count.
    // Reset estimated_tcp_congestion_window_ to be in sync with cubic.
    estimated_tcp_congestion_window_ = current_congestion_window;
    if (last_max_congestion_window_ <= current_congestion_window) {
      time_to_origin_point_ = 0;
      origin_point_congestion_window_ = current_congestion_window;
    } else {
      time_to_origin_point_ = static_cast<uint32_t>(
          cbrt(kCubeFactor *
               (last_max_congestion_window_ - current_congestion_window)));
      origin_point_congestion_window_ = last_max_congestion_window_;
    }
  } else {
    // If sender was app-limited, then freeze congestion window growth during
    // app-limited period. Continue growth now by shifting the epoch-start
    // through the app-limited period.
    if (FLAGS_shift_quic_cubic_epoch_when_app_limited &&
        app_limited_start_time_ != QuicTime::Zero()) {
      QuicTime::Delta shift = current_time.Subtract(app_limited_start_time_);
      DVLOG(1) << "Shifting epoch for quiescence by " << shift.ToMicroseconds();
      epoch_ = epoch_.Add(shift);
      app_limited_start_time_ = QuicTime::Zero();
    }
  }

  // Change the time unit from microseconds to 2^10 fractions per second. Take
  // the round trip time in account. This is done to allow us to use shift as a
  // divide operator.
  int64_t elapsed_time =
      (current_time.Add(delay_min).Subtract(epoch_).ToMicroseconds() << 10) /
      kNumMicrosPerSecond;

  int64_t offset = time_to_origin_point_ - elapsed_time;
  QuicPacketCount delta_congestion_window =
      (kCubeCongestionWindowScale * offset * offset * offset) >> kCubeScale;

  QuicPacketCount target_congestion_window =
      origin_point_congestion_window_ - delta_congestion_window;

  DCHECK_LT(0u, estimated_tcp_congestion_window_);
  // With dynamic beta/alpha based on number of active streams, it is possible
  // for the required_ack_count to become much lower than acked_packets_count_
  // suddenly, leading to more than one iteration through the following loop.
  while (true) {
    // Update estimated TCP congestion_window.
    QuicPacketCount required_ack_count = static_cast<QuicPacketCount>(
        estimated_tcp_congestion_window_ / Alpha());
    if (acked_packets_count_ < required_ack_count) {
      break;
    }
    acked_packets_count_ -= required_ack_count;
    estimated_tcp_congestion_window_++;
  }

  // We have a new cubic congestion window.
  last_target_congestion_window_ = target_congestion_window;

  // Compute target congestion_window based on cubic target and estimated TCP
  // congestion_window, use highest (fastest).
  if (target_congestion_window < estimated_tcp_congestion_window_) {
    target_congestion_window = estimated_tcp_congestion_window_;
  }

  DVLOG(1) << "Final target congestion_window: " << target_congestion_window;
  return target_congestion_window;
}

}  // namespace net
