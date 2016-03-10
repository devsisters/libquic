// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/general_loss_algorithm.h"

#include "net/quic/congestion_control/rtt_stats.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_protocol.h"

namespace net {

namespace {

// The minimum delay before a packet will be considered lost,
// regardless of SRTT.  Half of the minimum TLP, since the loss algorithm only
// triggers when a nack has been receieved for the packet.
static const size_t kMinLossDelayMs = 5;

// How many RTTs the algorithm waits before determining a packet is lost due
// to early retransmission or by time based loss detection.
static const double kLossDelayMultiplier = 1.25;

}  // namespace

GeneralLossAlgorithm::GeneralLossAlgorithm()
    : loss_type_(kNack), loss_detection_timeout_(QuicTime::Zero()) {}

GeneralLossAlgorithm::GeneralLossAlgorithm(LossDetectionType loss_type)
    : loss_type_(loss_type), loss_detection_timeout_(QuicTime::Zero()) {}

LossDetectionType GeneralLossAlgorithm::GetLossDetectionType() const {
  return loss_type_;
}

// Uses nack counts to decide when packets are lost.
void GeneralLossAlgorithm::DetectLosses(
    const QuicUnackedPacketMap& unacked_packets,
    const QuicTime& time,
    const RttStats& rtt_stats,
    SendAlgorithmInterface::CongestionVector* packets_lost) {
  const QuicPacketNumber largest_observed = unacked_packets.largest_observed();
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

    // TODO(ianswett): Combine this and the time based detection for FACK.
    if (loss_type_ == kTime) {
      QuicTime when_lost = it->sent_time.Add(loss_delay);
      if (time < when_lost) {
        loss_detection_timeout_ = when_lost;
        break;
      }
      packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
      continue;
    }

    // FACK based loss detection.
    QUIC_BUG_IF(it->nack_count == 0 && it->sent_time.IsInitialized())
        << "All packets less than largest observed should have been nacked."
        << " packet_number:" << packet_number
        << " largest_observed:" << largest_observed;
    if (it->nack_count >= kNumberOfNacksBeforeRetransmission) {
      packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
      continue;
    }

    // NACK-based loss detection allows for a max reordering window of 1 RTT.
    if (it->sent_time.Add(rtt_stats.smoothed_rtt()) <
        unacked_packets.GetTransmissionInfo(largest_observed).sent_time) {
      packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
      continue;
    }

    // Only early retransmit(RFC5827) when the last packet gets acked and
    // there are retransmittable packets in flight.
    // This also implements a timer-protected variant of FACK.
    if (!it->retransmittable_frames.empty() &&
        unacked_packets.largest_sent_packet() == largest_observed) {
      // Early retransmit marks the packet as lost once 1.25RTTs have passed
      // since the packet was sent and otherwise sets an alarm.
      if (time >= it->sent_time.Add(loss_delay)) {
        packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
      } else {
        // Set the timeout for the earliest retransmittable packet where early
        // retransmit applies.
        loss_detection_timeout_ = it->sent_time.Add(loss_delay);
        break;
      }
    }
  }
}

QuicTime GeneralLossAlgorithm::GetLossTimeout() const {
  return loss_detection_timeout_;
}

}  // namespace net
