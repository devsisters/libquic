// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// TCP cubic send side congestion algorithm, emulates the behavior of TCP cubic.

#ifndef NET_QUIC_CONGESTION_CONTROL_TCP_CUBIC_SENDER_BASE_H_
#define NET_QUIC_CONGESTION_CONTROL_TCP_CUBIC_SENDER_BASE_H_

#include <stdint.h>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/quic/congestion_control/cubic.h"
#include "net/quic/congestion_control/hybrid_slow_start.h"
#include "net/quic/congestion_control/prr_sender.h"
#include "net/quic/congestion_control/send_algorithm_interface.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_connection_stats.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

class RttStats;

// Maximum window to allow when doing bandwidth resumption.
const QuicPacketCount kMaxResumptionCongestionWindow = 200;

namespace test {
class TcpCubicSenderBasePeer;
}  // namespace test

class NET_EXPORT_PRIVATE TcpCubicSenderBase : public SendAlgorithmInterface {
 public:
  // Reno option and max_tcp_congestion_window are provided for testing.
  TcpCubicSenderBase(const QuicClock* clock,
                     const RttStats* rtt_stats,
                     bool reno,
                     QuicConnectionStats* stats);
  ~TcpCubicSenderBase() override;

  // Start implementation of SendAlgorithmInterface.
  void SetFromConfig(const QuicConfig& config,
                     Perspective perspective) override;
  void ResumeConnectionState(
      const CachedNetworkParameters& cached_network_params,
      bool max_bandwidth_resumption) override;
  void SetNumEmulatedConnections(int num_connections) override;
  void OnCongestionEvent(bool rtt_updated,
                         QuicByteCount bytes_in_flight,
                         const CongestionVector& acked_packets,
                         const CongestionVector& lost_packets) override;
  bool OnPacketSent(QuicTime sent_time,
                    QuicByteCount bytes_in_flight,
                    QuicPacketNumber packet_number,
                    QuicByteCount bytes,
                    HasRetransmittableData is_retransmittable) override;
  void OnRetransmissionTimeout(bool packets_retransmitted) override;
  void OnConnectionMigration() override;
  QuicTime::Delta TimeUntilSend(QuicTime now,
                                QuicByteCount bytes_in_flight) const override;
  QuicBandwidth PacingRate(QuicByteCount bytes_in_flight) const override;
  QuicBandwidth BandwidthEstimate() const override;
  QuicTime::Delta RetransmissionDelay() const override;
  bool InSlowStart() const override;
  bool InRecovery() const override;

 protected:
  // Called when resuming a previous bandwidth.
  virtual void SetCongestionWindowFromBandwidthAndRtt(QuicBandwidth bandwidth,
                                                      QuicTime::Delta rtt) = 0;

  // Called when initializing the congestion window.
  virtual void SetCongestionWindowInPackets(
      QuicPacketCount congestion_window) = 0;

  // Called when initializing the minimum congestion window.
  virtual void SetMinCongestionWindowInPackets(
      QuicPacketCount congestion_window) = 0;

  // Called when slow start is exited to set SSTHRESH.
  virtual void ExitSlowstart() = 0;

  // Called when a packet is lost.
  virtual void OnPacketLost(QuicPacketNumber largest_loss,
                            QuicByteCount lost_bytes,
                            QuicByteCount bytes_in_flight) = 0;

  // Called when a packet has been acked to possibly increase the congestion
  // window.
  virtual void MaybeIncreaseCwnd(QuicPacketNumber acked_packet_number,
                                 QuicByteCount acked_bytes,
                                 QuicByteCount bytes_in_flight) = 0;

  // Called when a retransmission has occured which resulted in packets
  // being retransmitted.
  virtual void HandleRetransmissionTimeout() = 0;

  // Compute the TCP Reno beta based on the current number of connections.
  float RenoBeta() const;

  bool IsCwndLimited(QuicByteCount bytes_in_flight) const;

 private:
  friend class test::TcpCubicSenderBasePeer;

  // TODO(ianswett): Remove these and migrate to OnCongestionEvent.
  void OnPacketAcked(QuicPacketNumber acked_packet_number,
                     QuicByteCount acked_bytes,
                     QuicByteCount bytes_in_flight);

 protected:
  // TODO(rch): Make these private and clean up subclass access to them.
  HybridSlowStart hybrid_slow_start_;
  PrrSender prr_;
  const RttStats* rtt_stats_;
  QuicConnectionStats* stats_;

  // If true, Reno congestion control is used instead of Cubic.
  const bool reno_;

  // Number of connections to simulate.
  uint32_t num_connections_;

  // Track the largest packet that has been sent.
  QuicPacketNumber largest_sent_packet_number_;

  // Track the largest packet that has been acked.
  QuicPacketNumber largest_acked_packet_number_;

  // Track the largest packet number outstanding when a CWND cutback occurs.
  QuicPacketNumber largest_sent_at_last_cutback_;

  // Whether to use 4 packets as the actual min, but pace lower.
  bool min4_mode_;

  // Whether the last loss event caused us to exit slowstart.
  // Used for stats collection of slowstart_packets_lost
  bool last_cutback_exited_slowstart_;

  // When true, exit slow start with large cutback of congestion window.
  bool slow_start_large_reduction_;

  // When true, use rate based sending instead of only sending if there's CWND.
  bool rate_based_sending_;

  // When true, use unity pacing instead of PRR.
  bool no_prr_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TcpCubicSenderBase);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_TCP_CUBIC_SENDER_BASE_H_
