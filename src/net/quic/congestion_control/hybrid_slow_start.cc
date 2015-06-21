// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/hybrid_slow_start.h"

#include <algorithm>

using std::max;
using std::min;

namespace net {

// Note(pwestin): the magic clamping numbers come from the original code in
// tcp_cubic.c.
const int64 kHybridStartLowWindow = 16;
// Number of delay samples for detecting the increase of delay.
const uint32 kHybridStartMinSamples = 8;
// Exit slow start if the min rtt has increased by more than 1/8th.
const int kHybridStartDelayFactorExp = 3;  // 2^3 = 8
// The original paper specifies 2 and 8ms, but those have changed over time.
const int64 kHybridStartDelayMinThresholdUs = 4000;
const int64 kHybridStartDelayMaxThresholdUs = 16000;

HybridSlowStart::HybridSlowStart(const QuicClock* clock)
    : clock_(clock),
      started_(false),
      hystart_found_(NOT_FOUND),
      last_sent_sequence_number_(0),
      end_sequence_number_(0),
      rtt_sample_count_(0),
      current_min_rtt_(QuicTime::Delta::Zero()) {
}

void HybridSlowStart::OnPacketAcked(
    QuicPacketSequenceNumber acked_sequence_number, bool in_slow_start) {
  // OnPacketAcked gets invoked after ShouldExitSlowStart, so it's best to end
  // the round when the final packet of the burst is received and start it on
  // the next incoming ack.
  if (in_slow_start && IsEndOfRound(acked_sequence_number)) {
    started_ = false;
  }
}

void HybridSlowStart::OnPacketSent(QuicPacketSequenceNumber sequence_number) {
  last_sent_sequence_number_ = sequence_number;
}

void HybridSlowStart::Restart() {
  started_ = false;
  hystart_found_ = NOT_FOUND;
}

void HybridSlowStart::StartReceiveRound(QuicPacketSequenceNumber last_sent) {
  DVLOG(1) << "Reset hybrid slow start @" << last_sent;
  end_sequence_number_ = last_sent;
  current_min_rtt_ = QuicTime::Delta::Zero();
  rtt_sample_count_ = 0;
  started_ = true;
}

bool HybridSlowStart::IsEndOfRound(QuicPacketSequenceNumber ack) const {
  return end_sequence_number_ <= ack;
}

bool HybridSlowStart::ShouldExitSlowStart(QuicTime::Delta latest_rtt,
                                          QuicTime::Delta min_rtt,
                                          QuicPacketCount congestion_window) {
  if (!started_) {
    // Time to start the hybrid slow start.
    StartReceiveRound(last_sent_sequence_number_);
  }
  if (hystart_found_ != NOT_FOUND) {
    return true;
  }
  // Second detection parameter - delay increase detection.
  // Compare the minimum delay (current_min_rtt_) of the current
  // burst of packets relative to the minimum delay during the session.
  // Note: we only look at the first few(8) packets in each burst, since we
  // only want to compare the lowest RTT of the burst relative to previous
  // bursts.
  rtt_sample_count_++;
  if (rtt_sample_count_ <= kHybridStartMinSamples) {
    if (current_min_rtt_.IsZero() || current_min_rtt_ > latest_rtt) {
      current_min_rtt_ = latest_rtt;
    }
  }
  // We only need to check this once per round.
  if (rtt_sample_count_ == kHybridStartMinSamples) {
    // Divide min_rtt by 8 to get a rtt increase threshold for exiting.
    int64 min_rtt_increase_threshold_us = min_rtt.ToMicroseconds() >>
        kHybridStartDelayFactorExp;
    // Ensure the rtt threshold is never less than 2ms or more than 16ms.
    min_rtt_increase_threshold_us = min(min_rtt_increase_threshold_us,
                                        kHybridStartDelayMaxThresholdUs);
    QuicTime::Delta min_rtt_increase_threshold =
        QuicTime::Delta::FromMicroseconds(max(min_rtt_increase_threshold_us,
                                              kHybridStartDelayMinThresholdUs));

    if (current_min_rtt_ > min_rtt.Add(min_rtt_increase_threshold)) {
      hystart_found_= DELAY;
    }
  }
  // Exit from slow start if the cwnd is greater than 16 and
  // increasing delay is found.
  return congestion_window >= kHybridStartLowWindow &&
      hystart_found_ != NOT_FOUND;
}

}  // namespace net
