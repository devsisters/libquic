// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/send_algorithm_interface.h"

#include "net/quic/congestion_control/tcp_cubic_bytes_sender.h"
#include "net/quic/congestion_control/tcp_cubic_sender.h"
#include "net/quic/quic_protocol.h"

namespace net {

class RttStats;

// Factory for send side congestion control algorithm.
SendAlgorithmInterface* SendAlgorithmInterface::Create(
    const QuicClock* clock,
    const RttStats* rtt_stats,
    CongestionControlType congestion_control_type,
    QuicConnectionStats* stats,
    QuicPacketCount initial_congestion_window) {
  const QuicPacketCount max_congestion_window =
      (kDefaultSocketReceiveBuffer * kConservativeReceiveBufferFraction) /
      kDefaultTCPMSS;
  switch (congestion_control_type) {
    case kCubic:
      return new TcpCubicSender(clock, rtt_stats, false /* don't use Reno */,
                                initial_congestion_window,
                                max_congestion_window, stats);
    case kCubicBytes:
      return new TcpCubicBytesSender(
          clock, rtt_stats, false /* don't use Reno */,
          initial_congestion_window, max_congestion_window, stats);
    case kReno:
      return new TcpCubicSender(clock, rtt_stats, true /* use Reno */,
                                initial_congestion_window,
                                max_congestion_window, stats);
    case kRenoBytes:
      return new TcpCubicBytesSender(clock, rtt_stats, true /* use Reno */,
                                     initial_congestion_window,
                                     max_congestion_window, stats);
    case kBBR:
// TODO(rtenneti): Enable BbrTcpSender.
#if 0
      return new BbrTcpSender(clock, rtt_stats, initial_congestion_window,
                              max_congestion_window, stats, true);
#endif
      LOG(DFATAL) << "BbrTcpSender is not supported.";
      return nullptr;
  }
  return nullptr;
}

}  // namespace net
