// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/tcp_loss_algorithm.h"

#include "net/quic/congestion_control/rtt_stats.h"
#include "net/quic/quic_protocol.h"

namespace net {

namespace {

// The minimum delay before a packet will be considered lost,
// regardless of SRTT.  Half of the minimum TLP, since the loss algorithm only
// triggers when a nack has been receieved for the packet.
static const size_t kMinLossDelayMs = 5;

// How many RTTs the algorithm waits before determining a packet is lost due
// to early retransmission.
static const double kEarlyRetransmitLossDelayMultiplier = 1.25;

}  // namespace

TCPLossAlgorithm::TCPLossAlgorithm()
    : loss_detection_timeout_(QuicTime::Zero()) {}

LossDetectionType TCPLossAlgorithm::GetLossDetectionType() const {
  return kNack;
}

// Uses nack counts to decide when packets are lost.
PacketNumberSet TCPLossAlgorithm::DetectLostPackets(
    const QuicUnackedPacketMap& unacked_packets,
    const QuicTime& time,
    QuicPacketNumber largest_observed,
    const RttStats& rtt_stats) {
  PacketNumberSet lost_packets;
  loss_detection_timeout_ = QuicTime::Zero();
  QuicTime::Delta early_retransmit_delay = QuicTime::Delta::Max(
      QuicTime::Delta::FromMilliseconds(kMinLossDelayMs),
      rtt_stats.smoothed_rtt().Multiply(kEarlyRetransmitLossDelayMultiplier));

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
    if (it->nack_count >= kNumberOfNacksBeforeRetransmission) {
      lost_packets.insert(packet_number);
      continue;
    }

    // Immediately lose the packet if it's been an srtt between the sent time
    // of it and the largest observed.  This speeds recovery from timer based
    // retransmissions, such as TLP and RTO, when there may be fewer than
    // kNumberOfNacksBeforeRetransmission nacks.
    if (it->sent_time.Add(rtt_stats.smoothed_rtt()) <
        unacked_packets.GetTransmissionInfo(largest_observed).sent_time) {
      lost_packets.insert(packet_number);
      continue;
    }

    // Only early retransmit(RFC5827) when the last packet gets acked and
    // there are retransmittable packets in flight.
    // This also implements a timer-protected variant of FACK.
    if (it->retransmittable_frames &&
        unacked_packets.largest_sent_packet() == largest_observed) {
      // Early retransmit marks the packet as lost once 1.25RTTs have passed
      // since the packet was sent and otherwise sets an alarm.
      if (time >= it->sent_time.Add(early_retransmit_delay)) {
        lost_packets.insert(packet_number);
      } else {
        // Set the timeout for the earliest retransmittable packet where early
        // retransmit applies.
        loss_detection_timeout_ = it->sent_time.Add(early_retransmit_delay);
        break;
      }
    }
  }

  return lost_packets;
}

void TCPLossAlgorithm::DetectLosses(
    const QuicUnackedPacketMap& unacked_packets,
    const QuicTime& time,
    const RttStats& rtt_stats,
    SendAlgorithmInterface::CongestionVector* packets_lost) {
  LOG(DFATAL) << "DetectLoss is unsupported by TCPLossAlgorithm.";
}

QuicTime TCPLossAlgorithm::GetLossTimeout() const {
  return loss_detection_timeout_;
}

}  // namespace net
