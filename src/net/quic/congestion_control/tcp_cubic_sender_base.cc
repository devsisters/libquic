// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/tcp_cubic_sender_packets.h"

#include <algorithm>

#include "base/metrics/histogram_macros.h"
#include "net/quic/congestion_control/prr_sender.h"
#include "net/quic/congestion_control/rtt_stats.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/proto/cached_network_parameters.pb.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_flags.h"

using std::max;
using std::min;

namespace net {

namespace {
// Constants based on TCP defaults.
// The minimum cwnd based on RFC 3782 (TCP NewReno) for cwnd reductions on a
// fast retransmission.  The cwnd after a timeout is still 1.
const QuicByteCount kMaxBurstBytes = 3 * kDefaultTCPMSS;
const float kRenoBeta = 0.7f;               // Reno backoff factor.
const uint32_t kDefaultNumConnections = 2;  // N-connection emulation.
const float kRateBasedExtraCwnd = 1.5f;     // CWND for rate based sending.
}  // namespace

TcpCubicSenderBase::TcpCubicSenderBase(const QuicClock* clock,
                                       const RttStats* rtt_stats,
                                       bool reno,
                                       QuicConnectionStats* stats)
    : rtt_stats_(rtt_stats),
      stats_(stats),
      reno_(reno),
      num_connections_(kDefaultNumConnections),
      largest_sent_packet_number_(0),
      largest_acked_packet_number_(0),
      largest_sent_at_last_cutback_(0),
      min4_mode_(false),
      last_cutback_exited_slowstart_(false),
      slow_start_large_reduction_(false),
      rate_based_sending_(false),
      no_prr_(false) {}

TcpCubicSenderBase::~TcpCubicSenderBase() {}

void TcpCubicSenderBase::SetFromConfig(const QuicConfig& config,
                                       Perspective perspective) {
  if (perspective == Perspective::IS_SERVER) {
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kIW03)) {
      // Initial window experiment.
      SetCongestionWindowInPackets(3);
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kIW10)) {
      // Initial window experiment.
      SetCongestionWindowInPackets(10);
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kIW20)) {
      // Initial window experiment.
      SetCongestionWindowInPackets(20);
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kIW50)) {
      // Initial window experiment.
      SetCongestionWindowInPackets(50);
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kMIN1)) {
      // Min CWND experiment.
      SetMinCongestionWindowInPackets(1);
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kMIN4)) {
      // Min CWND of 4 experiment.
      min4_mode_ = true;
      SetMinCongestionWindowInPackets(1);
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kSSLR)) {
      // Slow Start Fast Exit experiment.
      slow_start_large_reduction_ = true;
    }
    if (FLAGS_quic_allow_noprr && config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kNPRR)) {
      // Use unity pacing instead of PRR.
      no_prr_ = true;
    }
    if (FLAGS_quic_rate_based_sending &&
        config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kRATE)) {
      // Rate based sending experiment
      rate_based_sending_ = true;
    }
  }
}

void TcpCubicSenderBase::ResumeConnectionState(
    const CachedNetworkParameters& cached_network_params,
    bool max_bandwidth_resumption) {
  QuicBandwidth bandwidth = QuicBandwidth::FromBytesPerSecond(
      max_bandwidth_resumption
          ? cached_network_params.max_bandwidth_estimate_bytes_per_second()
          : cached_network_params.bandwidth_estimate_bytes_per_second());
  QuicTime::Delta rtt =
      QuicTime::Delta::FromMilliseconds(cached_network_params.min_rtt_ms());

  SetCongestionWindowFromBandwidthAndRtt(bandwidth, rtt);
}

void TcpCubicSenderBase::SetNumEmulatedConnections(int num_connections) {
  num_connections_ = max(1, num_connections);
}

float TcpCubicSenderBase::RenoBeta() const {
  // kNConnectionBeta is the backoff factor after loss for our N-connection
  // emulation, which emulates the effective backoff of an ensemble of N
  // TCP-Reno connections on a single loss event. The effective multiplier is
  // computed as:
  return (num_connections_ - 1 + kRenoBeta) / num_connections_;
}

void TcpCubicSenderBase::OnCongestionEvent(
    bool rtt_updated,
    QuicByteCount bytes_in_flight,
    const CongestionVector& acked_packets,
    const CongestionVector& lost_packets) {
  if (rtt_updated && InSlowStart() &&
      hybrid_slow_start_.ShouldExitSlowStart(
          rtt_stats_->latest_rtt(), rtt_stats_->min_rtt(),
          GetCongestionWindow() / kDefaultTCPMSS)) {
    ExitSlowstart();
  }
  for (CongestionVector::const_iterator it = lost_packets.begin();
       it != lost_packets.end(); ++it) {
    OnPacketLost(it->first, it->second, bytes_in_flight);
  }
  for (CongestionVector::const_iterator it = acked_packets.begin();
       it != acked_packets.end(); ++it) {
    OnPacketAcked(it->first, it->second, bytes_in_flight);
  }
}

void TcpCubicSenderBase::OnPacketAcked(QuicPacketNumber acked_packet_number,
                                       QuicByteCount acked_bytes,
                                       QuicByteCount bytes_in_flight) {
  largest_acked_packet_number_ =
      max(acked_packet_number, largest_acked_packet_number_);
  if (InRecovery()) {
    if (!no_prr_) {
      // PRR is used when in recovery.
      prr_.OnPacketAcked(acked_bytes);
    }
    return;
  }
  MaybeIncreaseCwnd(acked_packet_number, acked_bytes, bytes_in_flight);
  if (InSlowStart()) {
    hybrid_slow_start_.OnPacketAcked(acked_packet_number);
  }
}

bool TcpCubicSenderBase::OnPacketSent(
    QuicTime /*sent_time*/,
    QuicByteCount /*bytes_in_flight*/,
    QuicPacketNumber packet_number,
    QuicByteCount bytes,
    HasRetransmittableData is_retransmittable) {
  if (InSlowStart()) {
    ++(stats_->slowstart_packets_sent);
  }

  // Only update bytes_in_flight_ for data packets.
  if (is_retransmittable != HAS_RETRANSMITTABLE_DATA) {
    return false;
  }
  if (InRecovery()) {
    // PRR is used when in recovery.
    prr_.OnPacketSent(bytes);
  }
  DCHECK_LT(largest_sent_packet_number_, packet_number);
  largest_sent_packet_number_ = packet_number;
  hybrid_slow_start_.OnPacketSent(packet_number);
  return true;
}

QuicTime::Delta TcpCubicSenderBase::TimeUntilSend(
    QuicTime /* now */,
    QuicByteCount bytes_in_flight) const {
  if (!no_prr_ && InRecovery()) {
    // PRR is used when in recovery.
    return prr_.TimeUntilSend(GetCongestionWindow(), bytes_in_flight,
                              GetSlowStartThreshold());
  }
  if (GetCongestionWindow() > bytes_in_flight) {
    return QuicTime::Delta::Zero();
  }
  if (min4_mode_ && bytes_in_flight < 4 * kDefaultTCPMSS) {
    return QuicTime::Delta::Zero();
  }
  if (rate_based_sending_ &&
      GetCongestionWindow() * kRateBasedExtraCwnd > bytes_in_flight) {
    return QuicTime::Delta::Zero();
  }
  return QuicTime::Delta::Infinite();
}

QuicBandwidth TcpCubicSenderBase::PacingRate(
    QuicByteCount bytes_in_flight) const {
  // We pace at twice the rate of the underlying sender's bandwidth estimate
  // during slow start and 1.25x during congestion avoidance to ensure pacing
  // doesn't prevent us from filling the window.
  QuicTime::Delta srtt = rtt_stats_->smoothed_rtt();
  if (srtt.IsZero()) {
    srtt = QuicTime::Delta::FromMicroseconds(rtt_stats_->initial_rtt_us());
  }
  const QuicBandwidth bandwidth =
      QuicBandwidth::FromBytesAndTimeDelta(GetCongestionWindow(), srtt);
  if (rate_based_sending_ && bytes_in_flight > GetCongestionWindow()) {
    // Rate based sending allows sending more than CWND, but reduces the pacing
    // rate when the bytes in flight is more than the CWND to 75% of bandwidth.
    return bandwidth.Scale(0.75);
  }
  return bandwidth.Scale(InSlowStart() ? 2
                                       : (no_prr_ && InRecovery() ? 1 : 1.25));
}

QuicBandwidth TcpCubicSenderBase::BandwidthEstimate() const {
  QuicTime::Delta srtt = rtt_stats_->smoothed_rtt();
  if (srtt.IsZero()) {
    // If we haven't measured an rtt, the bandwidth estimate is unknown.
    return QuicBandwidth::Zero();
  }
  return QuicBandwidth::FromBytesAndTimeDelta(GetCongestionWindow(), srtt);
}

QuicTime::Delta TcpCubicSenderBase::RetransmissionDelay() const {
  if (rtt_stats_->smoothed_rtt().IsZero()) {
    return QuicTime::Delta::Zero();
  }
  return rtt_stats_->smoothed_rtt().Add(
      rtt_stats_->mean_deviation().Multiply(4));
}

bool TcpCubicSenderBase::InSlowStart() const {
  return GetCongestionWindow() < GetSlowStartThreshold();
}

bool TcpCubicSenderBase::IsCwndLimited(QuicByteCount bytes_in_flight) const {
  const QuicByteCount congestion_window = GetCongestionWindow();
  if (bytes_in_flight >= congestion_window) {
    return true;
  }
  const QuicByteCount available_bytes = congestion_window - bytes_in_flight;
  const bool slow_start_limited =
      InSlowStart() && bytes_in_flight > congestion_window / 2;
  return slow_start_limited || available_bytes <= kMaxBurstBytes;
}

bool TcpCubicSenderBase::InRecovery() const {
  return largest_acked_packet_number_ <= largest_sent_at_last_cutback_ &&
         largest_acked_packet_number_ != 0;
}

void TcpCubicSenderBase::OnRetransmissionTimeout(bool packets_retransmitted) {
  largest_sent_at_last_cutback_ = 0;
  if (!packets_retransmitted) {
    return;
  }
  hybrid_slow_start_.Restart();
  HandleRetransmissionTimeout();
}

void TcpCubicSenderBase::OnConnectionMigration() {
  hybrid_slow_start_.Restart();
  prr_ = PrrSender();
  largest_sent_packet_number_ = 0;
  largest_acked_packet_number_ = 0;
  largest_sent_at_last_cutback_ = 0;
  last_cutback_exited_slowstart_ = false;
}

}  // namespace net
