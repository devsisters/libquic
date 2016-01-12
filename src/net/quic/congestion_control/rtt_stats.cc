// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/rtt_stats.h"

#include <cstdlib>  // std::abs

using std::max;

namespace net {

namespace {

// Default initial rtt used before any samples are received.
const int kInitialRttMs = 100;
const float kAlpha = 0.125f;
const float kOneMinusAlpha = (1 - kAlpha);
const float kBeta = 0.25f;
const float kOneMinusBeta = (1 - kBeta);
const float kHalfWindow = 0.5f;
const float kQuarterWindow = 0.25f;

}  // namespace

RttStats::RttStats()
    : latest_rtt_(QuicTime::Delta::Zero()),
      min_rtt_(QuicTime::Delta::Zero()),
      smoothed_rtt_(QuicTime::Delta::Zero()),
      mean_deviation_(QuicTime::Delta::Zero()),
      initial_rtt_us_(kInitialRttMs * kNumMicrosPerMilli),
      num_min_rtt_samples_remaining_(0),
      recent_min_rtt_window_(QuicTime::Delta::Infinite()) {}

void RttStats::SampleNewRecentMinRtt(uint32_t num_samples) {
  num_min_rtt_samples_remaining_ = num_samples;
  new_min_rtt_ = RttSample();
}

void RttStats::ExpireSmoothedMetrics() {
  mean_deviation_ =
      max(mean_deviation_,
          QuicTime::Delta::FromMicroseconds(
              std::abs(smoothed_rtt_.Subtract(latest_rtt_).ToMicroseconds())));
  smoothed_rtt_ = max(smoothed_rtt_, latest_rtt_);
}

// Updates the RTT based on a new sample.
void RttStats::UpdateRtt(QuicTime::Delta send_delta,
                         QuicTime::Delta ack_delay,
                         QuicTime now) {
  if (send_delta.IsInfinite() || send_delta <= QuicTime::Delta::Zero()) {
    LOG(WARNING) << "Ignoring measured send_delta, because it's is "
                 << "either infinite, zero, or negative.  send_delta = "
                 << send_delta.ToMicroseconds();
    return;
  }

  // Update min_rtt_ first. min_rtt_ does not use an rtt_sample corrected for
  // ack_delay but the raw observed send_delta, since poor clock granularity at
  // the client may cause a high ack_delay to result in underestimation of the
  // min_rtt_.
  if (min_rtt_.IsZero() || min_rtt_ > send_delta) {
    min_rtt_ = send_delta;
  }
  UpdateRecentMinRtt(send_delta, now);

  // Correct for ack_delay if information received from the peer results in a
  // positive RTT sample. Otherwise, we use the send_delta as a reasonable
  // measure for smoothed_rtt.
  QuicTime::Delta rtt_sample(send_delta);
  if (rtt_sample > ack_delay) {
    rtt_sample = rtt_sample.Subtract(ack_delay);
  }
  latest_rtt_ = rtt_sample;
  // First time call.
  if (smoothed_rtt_.IsZero()) {
    smoothed_rtt_ = rtt_sample;
    mean_deviation_ =
        QuicTime::Delta::FromMicroseconds(rtt_sample.ToMicroseconds() / 2);
  } else {
    mean_deviation_ = QuicTime::Delta::FromMicroseconds(static_cast<int64_t>(
        kOneMinusBeta * mean_deviation_.ToMicroseconds() +
        kBeta * std::abs(smoothed_rtt_.Subtract(rtt_sample).ToMicroseconds())));
    smoothed_rtt_ =
        smoothed_rtt_.Multiply(kOneMinusAlpha).Add(rtt_sample.Multiply(kAlpha));
    DVLOG(1) << " smoothed_rtt(us):" << smoothed_rtt_.ToMicroseconds()
             << " mean_deviation(us):" << mean_deviation_.ToMicroseconds();
  }
}

void RttStats::UpdateRecentMinRtt(QuicTime::Delta rtt_sample, QuicTime now) {
  // Recent min_rtt update.
  if (num_min_rtt_samples_remaining_ > 0) {
    --num_min_rtt_samples_remaining_;
    if (new_min_rtt_.rtt.IsZero() || rtt_sample <= new_min_rtt_.rtt) {
      new_min_rtt_ = RttSample(rtt_sample, now);
    }
    if (num_min_rtt_samples_remaining_ == 0) {
      quarter_window_rtt_ = half_window_rtt_ = recent_min_rtt_ = new_min_rtt_;
    }
  }

  // Update the three recent rtt samples.
  if (recent_min_rtt_.rtt.IsZero() || rtt_sample <= recent_min_rtt_.rtt) {
    recent_min_rtt_ = RttSample(rtt_sample, now);
    quarter_window_rtt_ = half_window_rtt_ = recent_min_rtt_;
  } else if (rtt_sample <= half_window_rtt_.rtt) {
    half_window_rtt_ = RttSample(rtt_sample, now);
    quarter_window_rtt_ = half_window_rtt_;
  } else if (rtt_sample <= quarter_window_rtt_.rtt) {
    quarter_window_rtt_ = RttSample(rtt_sample, now);
  }

  // Expire old min rtt samples.
  if (recent_min_rtt_.time < now.Subtract(recent_min_rtt_window_)) {
    recent_min_rtt_ = half_window_rtt_;
    half_window_rtt_ = quarter_window_rtt_;
    quarter_window_rtt_ = RttSample(rtt_sample, now);
  } else if (half_window_rtt_.time <
             now.Subtract(recent_min_rtt_window_.Multiply(kHalfWindow))) {
    half_window_rtt_ = quarter_window_rtt_;
    quarter_window_rtt_ = RttSample(rtt_sample, now);
  } else if (quarter_window_rtt_.time <
             now.Subtract(recent_min_rtt_window_.Multiply(kQuarterWindow))) {
    quarter_window_rtt_ = RttSample(rtt_sample, now);
  }
}

void RttStats::OnConnectionMigration() {
  latest_rtt_ = QuicTime::Delta::Zero();
  min_rtt_ = QuicTime::Delta::Zero();
  smoothed_rtt_ = QuicTime::Delta::Zero();
  mean_deviation_ = QuicTime::Delta::Zero();
  initial_rtt_us_ = kInitialRttMs * kNumMicrosPerMilli;
  num_min_rtt_samples_remaining_ = 0;
  recent_min_rtt_window_ = QuicTime::Delta::Infinite();
  recent_min_rtt_ = half_window_rtt_ = quarter_window_rtt_ = RttSample();
}

}  // namespace net
