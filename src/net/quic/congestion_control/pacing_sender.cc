// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/pacing_sender.h"

using std::min;

namespace net {

PacingSender::PacingSender(SendAlgorithmInterface* sender,
                           QuicTime::Delta alarm_granularity,
                           uint32_t initial_packet_burst)
    : sender_(sender),
      alarm_granularity_(alarm_granularity),
      initial_packet_burst_(initial_packet_burst),
      burst_tokens_(initial_packet_burst),
      last_delayed_packet_sent_time_(QuicTime::Zero()),
      ideal_next_packet_send_time_(QuicTime::Zero()),
      was_last_send_delayed_(false) {}

PacingSender::~PacingSender() {}

void PacingSender::SetFromConfig(const QuicConfig& config,
                                 Perspective perspective) {
  sender_->SetFromConfig(config, perspective);
}

void PacingSender::ResumeConnectionState(
    const CachedNetworkParameters& cached_network_params,
    bool max_bandwidth_resumption) {
  sender_->ResumeConnectionState(cached_network_params,
                                 max_bandwidth_resumption);
}

void PacingSender::SetNumEmulatedConnections(int num_connections) {
  sender_->SetNumEmulatedConnections(num_connections);
}

void PacingSender::SetMaxCongestionWindow(QuicByteCount max_congestion_window) {
  sender_->SetMaxCongestionWindow(max_congestion_window);
}

void PacingSender::OnCongestionEvent(bool rtt_updated,
                                     QuicByteCount bytes_in_flight,
                                     const CongestionVector& acked_packets,
                                     const CongestionVector& lost_packets) {
  sender_->OnCongestionEvent(rtt_updated, bytes_in_flight, acked_packets,
                             lost_packets);
}

bool PacingSender::OnPacketSent(
    QuicTime sent_time,
    QuicByteCount bytes_in_flight,
    QuicPacketNumber packet_number,
    QuicByteCount bytes,
    HasRetransmittableData has_retransmittable_data) {
  const bool in_flight =
      sender_->OnPacketSent(sent_time, bytes_in_flight, packet_number, bytes,
                            has_retransmittable_data);
  if (has_retransmittable_data != HAS_RETRANSMITTABLE_DATA) {
    return in_flight;
  }
  // If in recovery, the connection is not coming out of quiescence.
  if (bytes_in_flight == 0 && !sender_->InRecovery()) {
    // Add more burst tokens anytime the connection is leaving quiescence, but
    // limit it to the equivalent of a single bulk write, not exceeding the
    // current CWND in packets.
    burst_tokens_ = min(
        initial_packet_burst_,
        static_cast<uint32_t>(sender_->GetCongestionWindow() / kDefaultTCPMSS));
  }
  if (burst_tokens_ > 0) {
    --burst_tokens_;
    was_last_send_delayed_ = false;
    last_delayed_packet_sent_time_ = QuicTime::Zero();
    ideal_next_packet_send_time_ = QuicTime::Zero();
    return in_flight;
  }
  // The next packet should be sent as soon as the current packets has been
  // transferred.
  QuicTime::Delta delay = PacingRate().TransferTime(bytes);
  // If the last send was delayed, and the alarm took a long time to get
  // invoked, allow the connection to make up for lost time.
  if (was_last_send_delayed_) {
    ideal_next_packet_send_time_ = ideal_next_packet_send_time_.Add(delay);
    // The send was application limited if it takes longer than the
    // pacing delay between sent packets.
    const bool application_limited =
        last_delayed_packet_sent_time_.IsInitialized() &&
        sent_time > last_delayed_packet_sent_time_.Add(delay);
    const bool making_up_for_lost_time =
        ideal_next_packet_send_time_ <= sent_time;
    // As long as we're making up time and not application limited,
    // continue to consider the packets delayed, allowing the packets to be
    // sent immediately.
    if (making_up_for_lost_time && !application_limited) {
      last_delayed_packet_sent_time_ = sent_time;
    } else {
      was_last_send_delayed_ = false;
      last_delayed_packet_sent_time_ = QuicTime::Zero();
    }
  } else {
    ideal_next_packet_send_time_ = QuicTime::Max(
        ideal_next_packet_send_time_.Add(delay), sent_time.Add(delay));
  }
  return in_flight;
}

void PacingSender::OnRetransmissionTimeout(bool packets_retransmitted) {
  sender_->OnRetransmissionTimeout(packets_retransmitted);
}

QuicTime::Delta PacingSender::TimeUntilSend(
    QuicTime now,
    QuicByteCount bytes_in_flight,
    HasRetransmittableData has_retransmittable_data) const {
  QuicTime::Delta time_until_send =
      sender_->TimeUntilSend(now, bytes_in_flight, has_retransmittable_data);
  if (burst_tokens_ > 0 || bytes_in_flight == 0) {
    // Don't pace if we have burst tokens available or leaving quiescence.
    return time_until_send;
  }

  if (!time_until_send.IsZero()) {
    DCHECK(time_until_send.IsInfinite());
    // The underlying sender prevents sending.
    return time_until_send;
  }

  if (has_retransmittable_data == NO_RETRANSMITTABLE_DATA) {
    // Don't pace ACK packets, since they do not count against CWND and do not
    // cause CWND to grow.
    return QuicTime::Delta::Zero();
  }

  // If the next send time is within the alarm granularity, send immediately.
  if (ideal_next_packet_send_time_ > now.Add(alarm_granularity_)) {
    DVLOG(1) << "Delaying packet: "
             << ideal_next_packet_send_time_.Subtract(now).ToMicroseconds();
    was_last_send_delayed_ = true;
    return ideal_next_packet_send_time_.Subtract(now);
  }

  DVLOG(1) << "Sending packet now";
  return QuicTime::Delta::Zero();
}

QuicBandwidth PacingSender::PacingRate() const {
  return sender_->PacingRate();
}

QuicBandwidth PacingSender::BandwidthEstimate() const {
  return sender_->BandwidthEstimate();
}

QuicTime::Delta PacingSender::RetransmissionDelay() const {
  return sender_->RetransmissionDelay();
}

QuicByteCount PacingSender::GetCongestionWindow() const {
  return sender_->GetCongestionWindow();
}

bool PacingSender::InSlowStart() const {
  return sender_->InSlowStart();
}

bool PacingSender::InRecovery() const {
  return sender_->InRecovery();
}

QuicByteCount PacingSender::GetSlowStartThreshold() const {
  return sender_->GetSlowStartThreshold();
}

CongestionControlType PacingSender::GetCongestionControlType() const {
  return sender_->GetCongestionControlType();
}

}  // namespace net
