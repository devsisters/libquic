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
      slowstart_packets_sent(0),
      slowstart_packets_lost(0),
      packets_revived(0),
      packets_dropped(0),
      crypto_retransmit_count(0),
      loss_timeout_count(0),
      tlp_count(0),
      rto_count(0),
      min_rtt_us(0),
      srtt_us(0),
      max_packet_size(0),
      max_received_packet_size(0),
      estimated_bandwidth(QuicBandwidth::Zero()),
      packets_reordered(0),
      max_sequence_reordering(0),
      max_time_reordering_us(0),
      tcp_loss_events(0),
      connection_creation_time(QuicTime::Zero()) {}

QuicConnectionStats::~QuicConnectionStats() {}

}  // namespace net
