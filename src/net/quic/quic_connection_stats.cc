// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_connection_stats.h"

using std::ostream;

namespace net {

QuicConnectionStats::QuicConnectionStats()
    : bytes_sent(0),
      packets_sent(0),
      stream_bytes_sent(0),
      packets_discarded(0),
      bytes_received(0),
      packets_received(0),
      packets_processed(0),
      stream_bytes_received(0),
      bytes_retransmitted(0),
      packets_retransmitted(0),
      bytes_spuriously_retransmitted(0),
      packets_spuriously_retransmitted(0),
      packets_lost(0),
      slowstart_packets_lost(0),
      packets_revived(0),
      packets_dropped(0),
      crypto_retransmit_count(0),
      loss_timeout_count(0),
      tlp_count(0),
      rto_count(0),
      spurious_rto_count(0),
      min_rtt_us(0),
      srtt_us(0),
      max_packet_size(0),
      estimated_bandwidth(QuicBandwidth::Zero()),
      packets_reordered(0),
      max_sequence_reordering(0),
      max_time_reordering_us(0),
      tcp_loss_events(0),
      cwnd_increase_congestion_avoidance(0),
      cwnd_increase_cubic_mode(0),
      connection_creation_time(QuicTime::Zero()) {
}

QuicConnectionStats::~QuicConnectionStats() {}

ostream& operator<<(ostream& os, const QuicConnectionStats& s) {
  os << "{ bytes sent: " << s.bytes_sent
     << ", packets sent:" << s.packets_sent
     << ", stream bytes sent: " << s.stream_bytes_sent
     << ", packets discarded: " << s.packets_discarded
     << ", bytes received: " << s.bytes_received
     << ", packets received: " << s.packets_received
     << ", packets processed: " << s.packets_processed
     << ", stream bytes received: " << s.stream_bytes_received
     << ", bytes retransmitted: " << s.bytes_retransmitted
     << ", packets retransmitted: " << s.packets_retransmitted
     << ", bytes spuriously retransmitted: " << s.bytes_spuriously_retransmitted
     << ", packets spuriously retransmitted: "
     << s.packets_spuriously_retransmitted
     << ", packets lost: " << s.packets_lost
     << ", slowstart packets lost: " << s.slowstart_packets_lost
     << ", packets revived: " << s.packets_revived
     << ", packets dropped:" << s.packets_dropped
     << ", crypto retransmit count: " << s.crypto_retransmit_count
     << ", tlp count: " << s.tlp_count
     << ", rto count: " << s.rto_count
     << ", spurious_rto_count:" << s.spurious_rto_count
     << ", min_rtt(us): " << s.min_rtt_us
     << ", srtt(us): " << s.srtt_us
     << ", max packet size: " << s.max_packet_size
     << ", estimated bandwidth: " << s.estimated_bandwidth.ToBytesPerSecond()
     << ", tcp_loss_events: " << s.tcp_loss_events
     << ", packets reordered: " << s.packets_reordered
     << ", max sequence reordering: " << s.max_sequence_reordering
     << ", max time reordering(us): " << s.max_time_reordering_us
     << ", total amount of cwnd increase in TCPCubic, in congestion avoidance: "
     << s.cwnd_increase_congestion_avoidance
     << ", amount of cwnd increase in TCPCubic, in cubic mode: "
     << s.cwnd_increase_cubic_mode
     << "}\n";
  return os;
}

}  // namespace net
