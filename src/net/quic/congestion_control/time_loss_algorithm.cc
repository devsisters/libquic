// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/time_loss_algorithm.h"

#include "net/quic/congestion_control/rtt_stats.h"
#include "net/quic/quic_protocol.h"

namespace net {
namespace {

// The minimum delay before a packet will be considered lost,
// regardless of SRTT.  Half of the minimum TLP, since the loss algorithm only
// triggers when a nack has been receieved for the packet.
static const size_t kMinLossDelayMs = 5;

// How many RTTs the algorithm waits before determining a packet is lost.
static const double kLossDelayMultiplier = 1.25;

}  // namespace

TimeLossAlgorithm::TimeLossAlgorithm()
    : loss_detection_timeout_(QuicTime::Zero()) {}

LossDetectionType TimeLossAlgorithm::GetLossDetectionType() const {
  return kTime;
}

PacketNumberSet TimeLossAlgorithm::DetectLostPackets(
    const QuicUnackedPacketMap& unacked_packets,
    const QuicTime& time,
    QuicPacketNumber largest_observed,
    const RttStats& rtt_stats) {
  PacketNumberSet lost_packets;
  loss_detection_timeout_ = QuicTime::Zero();
  QuicTime::Delta loss_delay = QuicTime::Delta::Max(
      QuicTime::Delta::FromMilliseconds(kMinLossDelayMs),
      QuicTime::Delta::Max(rtt_stats.smoothed_rtt(), rtt_stats.latest_rtt())
          .Multiply(kLossDelayMultiplier));

  QuicPacketNumber packet_number = unacked_packets.GetLeastUnacked();
  for (QuicUnackedPacketMap::const_iterator it = unacked_packets.begin();
       it != unacked_packets.end() && packet_number <= largest_observed;
       ++it, ++packet_number) {
    if (!it->in_flight) {
      continue;
    }
    LOG_IF(DFATAL, it->nack_count == 0 && it->sent_time.IsInitialized())
        << "All packets less than largest observed should have been nacked."
        << "packet_number:" << packet_number
        << " largest_observed:" << largest_observed;

    // Packets are sent in order, so break when we haven't waited long enough
    // to lose any more packets and leave the loss_time_ set for the timeout.
    QuicTime when_lost = it->sent_time.Add(loss_delay);
    if (time < when_lost) {
      loss_detection_timeout_ = when_lost;
      break;
    }
    lost_packets.insert(packet_number);
  }

  return lost_packets;
}

void TimeLossAlgorithm::DetectLosses(
    const QuicUnackedPacketMap& unacked_packets,
    const QuicTime& time,
    const RttStats& rtt_stats,
    SendAlgorithmInterface::CongestionVector* packets_lost) {
  LOG(DFATAL) << "DetectLoss is unsupported by TimeLossAlgorithm.";
}

// loss_time_ is updated in DetectLostPackets, which must be called every time
// an ack is received or the timeout expires.
QuicTime TimeLossAlgorithm::GetLossTimeout() const {
  return loss_detection_timeout_;
}

}  // namespace net
