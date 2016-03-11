// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/tcp_cubic_sender.h"

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
const QuicPacketCount kDefaultMinimumCongestionWindow = 2;
const QuicByteCount kMaxBurstBytes = 3 * kDefaultTCPMSS;
const float kRenoBeta = 0.7f;             // Reno backoff factor.
const uint32_t kDefaultNumConnections = 2;  // N-connection emulation.
}  // namespace

TcpCubicSender::TcpCubicSender(const QuicClock* clock,
                               const RttStats* rtt_stats,
                               bool reno,
                               QuicPacketCount initial_tcp_congestion_window,
                               QuicPacketCount max_tcp_congestion_window,
                               QuicConnectionStats* stats)
    : cubic_(clock),
      rtt_stats_(rtt_stats),
      stats_(stats),
      reno_(reno),
      num_connections_(kDefaultNumConnections),
      congestion_window_count_(0),
      largest_sent_packet_number_(0),
      largest_acked_packet_number_(0),
      largest_sent_at_last_cutback_(0),
      congestion_window_(initial_tcp_congestion_window),
      min_congestion_window_(kDefaultMinimumCongestionWindow),
      min4_mode_(false),
      slowstart_threshold_(max_tcp_congestion_window),
      last_cutback_exited_slowstart_(false),
      max_tcp_congestion_window_(max_tcp_congestion_window),
      initial_tcp_congestion_window_(initial_tcp_congestion_window),
      initial_max_tcp_congestion_window_(max_tcp_congestion_window),
      slow_start_large_reduction_(false) {}

TcpCubicSender::~TcpCubicSender() {
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.FinalTcpCwnd", congestion_window_);
}

void TcpCubicSender::SetFromConfig(const QuicConfig& config,
                                   Perspective perspective) {
  if (perspective == Perspective::IS_SERVER) {
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kIW03)) {
      // Initial window experiment.
      congestion_window_ = 3;
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kIW10)) {
      // Initial window experiment.
      congestion_window_ = 10;
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kIW20)) {
      // Initial window experiment.
      congestion_window_ = 20;
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kIW50)) {
      // Initial window experiment.
      congestion_window_ = 50;
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kMIN1)) {
      // Min CWND experiment.
      min_congestion_window_ = 1;
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kMIN4)) {
      // Min CWND of 4 experiment.
      min4_mode_ = true;
      min_congestion_window_ = 1;
    }
    if (config.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config.ReceivedConnectionOptions(), kSSLR)) {
      // Slow Start Fast Exit experiment.
      slow_start_large_reduction_ = true;
    }
  }
}

void TcpCubicSender::ResumeConnectionState(
    const CachedNetworkParameters& cached_network_params,
    bool max_bandwidth_resumption) {
  QuicBandwidth bandwidth = QuicBandwidth::FromBytesPerSecond(
      max_bandwidth_resumption
          ? cached_network_params.max_bandwidth_estimate_bytes_per_second()
          : cached_network_params.bandwidth_estimate_bytes_per_second());
  QuicTime::Delta rtt_ms =
      QuicTime::Delta::FromMilliseconds(cached_network_params.min_rtt_ms());

  // Make sure CWND is in appropriate range (in case of bad data).
  QuicPacketCount new_congestion_window =
      bandwidth.ToBytesPerPeriod(rtt_ms) / kDefaultTCPMSS;
  congestion_window_ = max(min(new_congestion_window, kMaxCongestionWindow),
                           kMinCongestionWindowForBandwidthResumption);
}

void TcpCubicSender::SetNumEmulatedConnections(int num_connections) {
  num_connections_ = max(1, num_connections);
  cubic_.SetNumConnections(num_connections_);
}

void TcpCubicSender::SetMaxCongestionWindow(
    QuicByteCount max_congestion_window) {
  max_tcp_congestion_window_ = max_congestion_window / kDefaultTCPMSS;
}

float TcpCubicSender::RenoBeta() const {
  // kNConnectionBeta is the backoff factor after loss for our N-connection
  // emulation, which emulates the effective backoff of an ensemble of N
  // TCP-Reno connections on a single loss event. The effective multiplier is
  // computed as:
  return (num_connections_ - 1 + kRenoBeta) / num_connections_;
}

void TcpCubicSender::OnCongestionEvent(bool rtt_updated,
                                       QuicByteCount bytes_in_flight,
                                       const CongestionVector& acked_packets,
                                       const CongestionVector& lost_packets) {
  if (rtt_updated && InSlowStart() &&
      hybrid_slow_start_.ShouldExitSlowStart(rtt_stats_->latest_rtt(),
                                             rtt_stats_->min_rtt(),
                                             congestion_window_)) {
    slowstart_threshold_ = congestion_window_;
  }
  for (CongestionVector::const_iterator it = lost_packets.begin();
       it != lost_packets.end(); ++it) {
    OnPacketLost(it->first, bytes_in_flight);
  }
  for (CongestionVector::const_iterator it = acked_packets.begin();
       it != acked_packets.end(); ++it) {
    OnPacketAcked(it->first, it->second, bytes_in_flight);
  }
}

void TcpCubicSender::OnPacketAcked(QuicPacketNumber acked_packet_number,
                                   QuicByteCount acked_bytes,
                                   QuicByteCount bytes_in_flight) {
  largest_acked_packet_number_ =
      max(acked_packet_number, largest_acked_packet_number_);
  if (InRecovery()) {
    // PRR is used when in recovery.
    prr_.OnPacketAcked(acked_bytes);
    return;
  }
  MaybeIncreaseCwnd(acked_packet_number, bytes_in_flight);
  if (InSlowStart()) {
    hybrid_slow_start_.OnPacketAcked(acked_packet_number);
  }
}

void TcpCubicSender::OnPacketLost(QuicPacketNumber packet_number,
                                  QuicByteCount bytes_in_flight) {
  // TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
  // already sent should be treated as a single loss event, since it's expected.
  if (packet_number <= largest_sent_at_last_cutback_) {
    if (last_cutback_exited_slowstart_) {
      ++stats_->slowstart_packets_lost;
      if (slow_start_large_reduction_) {
        // Reduce congestion window by 1 for every loss.
        congestion_window_ =
            max(congestion_window_ - 1, min_congestion_window_);
        slowstart_threshold_ = congestion_window_;
      }
    }
    DVLOG(1) << "Ignoring loss for largest_missing:" << packet_number
             << " because it was sent prior to the last CWND cutback.";
    return;
  }
  ++stats_->tcp_loss_events;
  last_cutback_exited_slowstart_ = InSlowStart();
  if (InSlowStart()) {
    ++stats_->slowstart_packets_lost;
  }

  prr_.OnPacketLost(bytes_in_flight);

  // TODO(jri): Separate out all of slow start into a separate class.
  if (slow_start_large_reduction_ && InSlowStart()) {
    DCHECK_LT(1u, congestion_window_);
    congestion_window_ = congestion_window_ - 1;
  } else if (reno_) {
    congestion_window_ = congestion_window_ * RenoBeta();
  } else {
    congestion_window_ =
        cubic_.CongestionWindowAfterPacketLoss(congestion_window_);
  }
  // Enforce a minimum congestion window.
  if (congestion_window_ < min_congestion_window_) {
    congestion_window_ = min_congestion_window_;
  }
  slowstart_threshold_ = congestion_window_;
  largest_sent_at_last_cutback_ = largest_sent_packet_number_;
  // reset packet count from congestion avoidance mode. We start
  // counting again when we're out of recovery.
  congestion_window_count_ = 0;
  DVLOG(1) << "Incoming loss; congestion window: " << congestion_window_
           << " slowstart threshold: " << slowstart_threshold_;
}

bool TcpCubicSender::OnPacketSent(QuicTime /*sent_time*/,
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

QuicTime::Delta TcpCubicSender::TimeUntilSend(
    QuicTime /* now */,
    QuicByteCount bytes_in_flight,
    HasRetransmittableData has_retransmittable_data) const {
  if (has_retransmittable_data == NO_RETRANSMITTABLE_DATA) {
    DCHECK(!FLAGS_quic_respect_send_alarm2);
    // For TCP we can always send an ACK immediately.
    return QuicTime::Delta::Zero();
  }
  if (InRecovery()) {
    // PRR is used when in recovery.
    return prr_.TimeUntilSend(GetCongestionWindow(), bytes_in_flight,
                              slowstart_threshold_ * kDefaultTCPMSS);
  }
  if (GetCongestionWindow() > bytes_in_flight) {
    return QuicTime::Delta::Zero();
  }
  if (min4_mode_ && bytes_in_flight < 4 * kDefaultTCPMSS) {
    return QuicTime::Delta::Zero();
  }
  return QuicTime::Delta::Infinite();
}

QuicBandwidth TcpCubicSender::PacingRate() const {
  // We pace at twice the rate of the underlying sender's bandwidth estimate
  // during slow start and 1.25x during congestion avoidance to ensure pacing
  // doesn't prevent us from filling the window.
  QuicTime::Delta srtt = rtt_stats_->smoothed_rtt();
  if (srtt.IsZero()) {
    srtt = QuicTime::Delta::FromMicroseconds(rtt_stats_->initial_rtt_us());
  }
  const QuicBandwidth bandwidth =
      QuicBandwidth::FromBytesAndTimeDelta(GetCongestionWindow(), srtt);
  return bandwidth.Scale(InSlowStart() ? 2 : 1.25);
}

QuicBandwidth TcpCubicSender::BandwidthEstimate() const {
  QuicTime::Delta srtt = rtt_stats_->smoothed_rtt();
  if (srtt.IsZero()) {
    // If we haven't measured an rtt, the bandwidth estimate is unknown.
    return QuicBandwidth::Zero();
  }
  return QuicBandwidth::FromBytesAndTimeDelta(GetCongestionWindow(), srtt);
}

QuicTime::Delta TcpCubicSender::RetransmissionDelay() const {
  if (rtt_stats_->smoothed_rtt().IsZero()) {
    return QuicTime::Delta::Zero();
  }
  return rtt_stats_->smoothed_rtt().Add(
      rtt_stats_->mean_deviation().Multiply(4));
}

QuicByteCount TcpCubicSender::GetCongestionWindow() const {
  return congestion_window_ * kDefaultTCPMSS;
}

bool TcpCubicSender::InSlowStart() const {
  return congestion_window_ < slowstart_threshold_;
}

QuicByteCount TcpCubicSender::GetSlowStartThreshold() const {
  return slowstart_threshold_ * kDefaultTCPMSS;
}

bool TcpCubicSender::IsCwndLimited(QuicByteCount bytes_in_flight) const {
  const QuicByteCount congestion_window_bytes = GetCongestionWindow();
  if (bytes_in_flight >= congestion_window_bytes) {
    return true;
  }
  const QuicByteCount available_bytes =
      congestion_window_bytes - bytes_in_flight;
  const bool slow_start_limited =
      InSlowStart() && bytes_in_flight > congestion_window_bytes / 2;
  return slow_start_limited || available_bytes <= kMaxBurstBytes;
}

bool TcpCubicSender::InRecovery() const {
  return largest_acked_packet_number_ <= largest_sent_at_last_cutback_ &&
         largest_acked_packet_number_ != 0;
}

// Called when we receive an ack. Normal TCP tracks how many packets one ack
// represents, but quic has a separate ack for each packet.
void TcpCubicSender::MaybeIncreaseCwnd(QuicPacketNumber acked_packet_number,
                                       QuicByteCount bytes_in_flight) {
  QUIC_BUG_IF(InRecovery()) << "Never increase the CWND during recovery.";
  // Do not increase the congestion window unless the sender is close to using
  // the current window.
  if (!IsCwndLimited(bytes_in_flight)) {
    cubic_.OnApplicationLimited();
    return;
  }
  if (congestion_window_ >= max_tcp_congestion_window_) {
    return;
  }
  if (InSlowStart()) {
    // TCP slow start, exponential growth, increase by one for each ACK.
    ++congestion_window_;
    DVLOG(1) << "Slow start; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_;
    return;
  }
  // Congestion avoidance
  if (reno_) {
    // Classic Reno congestion avoidance.
    ++congestion_window_count_;
    // Divide by num_connections to smoothly increase the CWND at a faster
    // rate than conventional Reno.
    if (congestion_window_count_ * num_connections_ >= congestion_window_) {
      ++congestion_window_;
      congestion_window_count_ = 0;
    }

    DVLOG(1) << "Reno; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_
             << " congestion window count: " << congestion_window_count_;
  } else {
    congestion_window_ = min(max_tcp_congestion_window_,
                             cubic_.CongestionWindowAfterAck(
                                 congestion_window_, rtt_stats_->min_rtt()));
    DVLOG(1) << "Cubic; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_;
  }
}

void TcpCubicSender::OnRetransmissionTimeout(bool packets_retransmitted) {
  largest_sent_at_last_cutback_ = 0;
  if (!packets_retransmitted) {
    return;
  }
  cubic_.Reset();
  hybrid_slow_start_.Restart();
  slowstart_threshold_ = congestion_window_ / 2;
  congestion_window_ = min_congestion_window_;
}

void TcpCubicSender::OnConnectionMigration() {
  hybrid_slow_start_.Restart();
  cubic_.Reset();
  prr_ = PrrSender();
  congestion_window_count_ = 0;
  largest_sent_packet_number_ = 0;
  largest_acked_packet_number_ = 0;
  largest_sent_at_last_cutback_ = 0;
  congestion_window_ = initial_tcp_congestion_window_;
  slowstart_threshold_ = initial_max_tcp_congestion_window_;
  last_cutback_exited_slowstart_ = false;
  max_tcp_congestion_window_ = initial_max_tcp_congestion_window_;
}

CongestionControlType TcpCubicSender::GetCongestionControlType() const {
  return reno_ ? kReno : kCubic;
}

}  // namespace net
