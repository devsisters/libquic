// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TCP cubic send side congestion algorithm, emulates the behavior of TCP cubic.

#ifndef NET_QUIC_CONGESTION_CONTROL_TCP_CUBIC_BYTES_SENDER_H_
#define NET_QUIC_CONGESTION_CONTROL_TCP_CUBIC_BYTES_SENDER_H_

#include "base/basictypes.h"
#include "net/base/net_export.h"
#include "net/quic/congestion_control/cubic_bytes.h"
#include "net/quic/congestion_control/hybrid_slow_start.h"
#include "net/quic/congestion_control/prr_sender.h"
#include "net/quic/congestion_control/send_algorithm_interface.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_connection_stats.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

class RttStats;

namespace test {
class TcpCubicBytesSenderPeer;
}  // namespace test

class NET_EXPORT_PRIVATE TcpCubicBytesSender : public SendAlgorithmInterface {
 public:
  TcpCubicBytesSender(const QuicClock* clock,
                      const RttStats* rtt_stats,
                      bool reno,
                      QuicPacketCount initial_tcp_congestion_window,
                      QuicPacketCount max_congestion_window,
                      QuicConnectionStats* stats);
  ~TcpCubicBytesSender() override;

  // Start implementation of SendAlgorithmInterface.
  void SetFromConfig(const QuicConfig& config,
                     Perspective perspective) override;
  bool ResumeConnectionState(
      const CachedNetworkParameters& cached_network_params,
      bool max_bandwidth_resumption) override;
  void SetNumEmulatedConnections(int num_connections) override;
  void SetMaxCongestionWindow(QuicByteCount max_congestion_window) override;
  void OnCongestionEvent(bool rtt_updated,
                         QuicByteCount bytes_in_flight,
                         const CongestionVector& acked_packets,
                         const CongestionVector& lost_packets) override;
  bool OnPacketSent(QuicTime sent_time,
                    QuicByteCount bytes_in_flight,
                    QuicPacketSequenceNumber sequence_number,
                    QuicByteCount bytes,
                    HasRetransmittableData is_retransmittable) override;
  void OnRetransmissionTimeout(bool packets_retransmitted) override;
  QuicTime::Delta TimeUntilSend(
      QuicTime now,
      QuicByteCount bytes_in_flight,
      HasRetransmittableData has_retransmittable_data) const override;
  QuicBandwidth PacingRate() const override;
  QuicBandwidth BandwidthEstimate() const override;
  bool HasReliableBandwidthEstimate() const override;
  QuicTime::Delta RetransmissionDelay() const override;
  QuicByteCount GetCongestionWindow() const override;
  bool InSlowStart() const override;
  bool InRecovery() const override;
  QuicByteCount GetSlowStartThreshold() const override;
  CongestionControlType GetCongestionControlType() const override;
  // End implementation of SendAlgorithmInterface.

 private:
  friend class test::TcpCubicBytesSenderPeer;

  // Compute the TCP Reno beta based on the current number of connections.
  float RenoBeta() const;

  // TODO(ianswett): Remove these and migrate to OnCongestionEvent.
  void OnPacketAcked(QuicPacketSequenceNumber acked_sequence_number,
                     QuicByteCount acked_bytes,
                     QuicByteCount bytes_in_flight);
  void OnPacketLost(QuicPacketSequenceNumber largest_loss,
                    QuicByteCount bytes_in_flight);

  void MaybeIncreaseCwnd(QuicPacketSequenceNumber acked_sequence_number,
                         QuicByteCount acked_bytes,
                         QuicByteCount bytes_in_flight);
  bool IsCwndLimited(QuicByteCount bytes_in_flight) const;

  HybridSlowStart hybrid_slow_start_;
  CubicBytes cubic_;
  PrrSender prr_;
  const RttStats* rtt_stats_;
  QuicConnectionStats* stats_;

  // If true, Reno congestion control is used instead of Cubic.
  const bool reno_;

  // Number of connections to simulate.
  uint32 num_connections_;

  // ACK counter for the Reno implementation.
  uint64 num_acked_packets_;

  // Track the largest packet that has been sent.
  QuicPacketSequenceNumber largest_sent_sequence_number_;

  // Track the largest packet that has been acked.
  QuicPacketSequenceNumber largest_acked_sequence_number_;

  // Track the largest sequence number outstanding when a CWND cutback occurs.
  QuicPacketSequenceNumber largest_sent_at_last_cutback_;

  // Congestion window in bytes.
  QuicByteCount congestion_window_;

  // Minimum congestion window in bytes.
  QuicByteCount min_congestion_window_;

  // Whether to use 4 packets as the actual min, but pace lower.
  bool min4_mode_;

  // Maximum congestion window in bytes.
  QuicByteCount max_congestion_window_;

  // Slow start congestion window in bytes, aka ssthresh.
  QuicByteCount slowstart_threshold_;

  // Whether the last loss event caused us to exit slowstart. Used for stats
  // collection of slowstart_packets_lost.
  bool last_cutback_exited_slowstart_;

  const QuicClock* clock_;

  DISALLOW_COPY_AND_ASSIGN(TcpCubicBytesSender);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_TCP_CUBIC_BYTES_SENDER_H_
