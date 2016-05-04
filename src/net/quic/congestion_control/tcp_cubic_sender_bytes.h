// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TCP cubic send side congestion algorithm, emulates the behavior of TCP cubic.

#ifndef NET_QUIC_CONGESTION_CONTROL_TCP_CUBIC_SENDER_BYTES_H_
#define NET_QUIC_CONGESTION_CONTROL_TCP_CUBIC_SENDER_BYTES_H_

#include <stdint.h>

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/quic/congestion_control/cubic_bytes.h"
#include "net/quic/congestion_control/hybrid_slow_start.h"
#include "net/quic/congestion_control/prr_sender.h"
#include "net/quic/congestion_control/tcp_cubic_sender_base.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_connection_stats.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

class RttStats;

namespace test {
class TcpCubicSenderBytesPeer;
}  // namespace test

class NET_EXPORT_PRIVATE TcpCubicSenderBytes : public TcpCubicSenderBase {
 public:
  TcpCubicSenderBytes(const QuicClock* clock,
                      const RttStats* rtt_stats,
                      bool reno,
                      QuicPacketCount initial_tcp_congestion_window,
                      QuicPacketCount max_congestion_window,
                      QuicConnectionStats* stats);
  ~TcpCubicSenderBytes() override;

  // Start implementation of SendAlgorithmInterface.
  void SetNumEmulatedConnections(int num_connections) override;
  void SetMaxCongestionWindow(QuicByteCount max_congestion_window) override;
  void OnConnectionMigration() override;
  QuicByteCount GetCongestionWindow() const override;
  QuicByteCount GetSlowStartThreshold() const override;
  CongestionControlType GetCongestionControlType() const override;
  // End implementation of SendAlgorithmInterface.

  QuicByteCount min_congestion_window() const { return min_congestion_window_; }

 protected:
  // TcpCubicSenderBase methods
  void SetCongestionWindowFromBandwidthAndRtt(QuicBandwidth bandwidth,
                                              QuicTime::Delta rtt) override;
  void SetCongestionWindowInPackets(QuicPacketCount congestion_window) override;
  void SetMinCongestionWindowInPackets(
      QuicPacketCount congestion_window) override;
  void ExitSlowstart() override;
  void OnPacketLost(QuicPacketNumber largest_loss,
                    QuicByteCount lost_bytes,
                    QuicByteCount bytes_in_flight) override;
  void MaybeIncreaseCwnd(QuicPacketNumber acked_packet_number,
                         QuicByteCount acked_bytes,
                         QuicByteCount bytes_in_flight) override;
  void HandleRetransmissionTimeout() override;

 private:
  friend class test::TcpCubicSenderBytesPeer;

  CubicBytes cubic_;

  // ACK counter for the Reno implementation.
  uint64_t num_acked_packets_;

  // Congestion window in bytes.
  QuicByteCount congestion_window_;

  // Minimum congestion window in bytes.
  QuicByteCount min_congestion_window_;

  // Maximum congestion window in bytes.
  QuicByteCount max_congestion_window_;

  // Slow start congestion window in bytes, aka ssthresh.
  QuicByteCount slowstart_threshold_;

  // Initial TCP congestion window in bytes. This variable can only be set when
  // this algorithm is created.
  const QuicByteCount initial_tcp_congestion_window_;

  // Initial maximum TCP congestion window in bytes. This variable can only be
  // set when this algorithm is created.
  const QuicByteCount initial_max_tcp_congestion_window_;

  // The minimum window when exiting slow start with large reduction.
  QuicByteCount min_slow_start_exit_window_;

  DISALLOW_COPY_AND_ASSIGN(TcpCubicSenderBytes);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_TCP_CUBIC_BYTES_SENDER_H_
