// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_CONNECTION_STATS_H_
#define NET_QUIC_QUIC_CONNECTION_STATS_H_

#include <ostream>

#include "base/basictypes.h"
#include "net/base/net_export.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {
// Structure to hold stats for a QuicConnection.
struct NET_EXPORT_PRIVATE QuicConnectionStats {
  QuicConnectionStats();
  ~QuicConnectionStats();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicConnectionStats& s);

  QuicByteCount bytes_sent;  // Includes retransmissions, fec.
  QuicPacketCount packets_sent;
  // Non-retransmitted bytes sent in a stream frame.
  QuicByteCount stream_bytes_sent;
  // Packets serialized and discarded before sending.
  QuicPacketCount packets_discarded;

  // These include version negotiation and public reset packets, which do not
  // have sequence numbers or frame data.
  QuicByteCount bytes_received;  // Includes duplicate data for a stream, fec.
  // Includes packets which were not processable.
  QuicPacketCount packets_received;
  // Excludes packets which were not processable.
  QuicPacketCount packets_processed;
  QuicByteCount stream_bytes_received;  // Bytes received in a stream frame.

  QuicByteCount bytes_retransmitted;
  QuicPacketCount packets_retransmitted;

  QuicByteCount bytes_spuriously_retransmitted;
  QuicPacketCount packets_spuriously_retransmitted;
  // Number of packets abandoned as lost by the loss detection algorithm.
  QuicPacketCount packets_lost;

  // Number of packets sent in slow start.
  QuicPacketCount slowstart_packets_sent;
  // Number of packets lost exiting slow start.
  QuicPacketCount slowstart_packets_lost;

  QuicPacketCount packets_revived;
  QuicPacketCount packets_dropped;  // Duplicate or less than least unacked.
  size_t crypto_retransmit_count;
  // Count of times the loss detection alarm fired.  At least one packet should
  // be lost when the alarm fires.
  size_t loss_timeout_count;
  size_t tlp_count;
  size_t rto_count;  // Count of times the rto timer fired.

  int64 min_rtt_us;  // Minimum RTT in microseconds.
  int64 srtt_us;  // Smoothed RTT in microseconds.
  QuicByteCount max_packet_size;
  QuicBandwidth estimated_bandwidth;

  // Reordering stats for received packets.
  // Number of packets received out of sequence number order.
  QuicPacketCount packets_reordered;
  // Maximum reordering observed in sequence space.
  QuicPacketSequenceNumber max_sequence_reordering;
  // Maximum reordering observed in microseconds
  int64 max_time_reordering_us;

  // The following stats are used only in TcpCubicSender.
  // The number of loss events from TCP's perspective.  Each loss event includes
  // one or more lost packets.
  uint32 tcp_loss_events;

  // Creation time, as reported by the QuicClock.
  QuicTime connection_creation_time;
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CONNECTION_STATS_H_
