// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_received_packet_manager.h"

#include <limits>
#include <utility>

#include "base/logging.h"
#include "base/stl_util.h"
#include "net/base/linked_hash_map.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_connection_stats.h"

using std::max;
using std::min;
using std::numeric_limits;

namespace net {

namespace {

// The maximum number of packets to ack immediately after a missing packet for
// fast retransmission to kick in at the sender.  This limit is created to
// reduce the number of acks sent that have no benefit for fast retransmission.
// Set to the number of nacks needed for fast retransmit plus one for protection
// against an ack loss
const size_t kMaxPacketsAfterNewMissing = 4;

}

QuicReceivedPacketManager::EntropyTracker::EntropyTracker()
    :  packets_entropy_hash_(0),
       first_gap_(1),
       largest_observed_(0) {
}

QuicReceivedPacketManager::EntropyTracker::~EntropyTracker() {}

QuicPacketEntropyHash QuicReceivedPacketManager::EntropyTracker::EntropyHash(
    QuicPacketSequenceNumber sequence_number) const {
  DCHECK_LE(sequence_number, largest_observed_);
  if (sequence_number == largest_observed_) {
    return packets_entropy_hash_;
  }

  DCHECK_GE(sequence_number, first_gap_);
  DCHECK_EQ(first_gap_ + packets_entropy_.size() - 1, largest_observed_);
  QuicPacketEntropyHash hash = packets_entropy_hash_;
  ReceivedEntropyHashes::const_reverse_iterator it = packets_entropy_.rbegin();
  for (QuicPacketSequenceNumber i = 0;
           i < (largest_observed_ - sequence_number); ++i, ++it) {
    hash ^= it->first;
  }
  return hash;
}

void QuicReceivedPacketManager::EntropyTracker::RecordPacketEntropyHash(
    QuicPacketSequenceNumber sequence_number,
    QuicPacketEntropyHash entropy_hash) {
  if (sequence_number < first_gap_) {
    DVLOG(1) << "Ignoring received packet entropy for sequence_number:"
             << sequence_number << " less than largest_peer_sequence_number:"
             << first_gap_;
    return;
  }
  // RecordPacketEntropyHash is only intended to be called once per packet.
  DCHECK(sequence_number > largest_observed_ ||
         !packets_entropy_[sequence_number - first_gap_].second);

  packets_entropy_hash_ ^= entropy_hash;

  // Optimize the typical case of no gaps.
  if (sequence_number == largest_observed_ + 1 && packets_entropy_.empty()) {
    ++first_gap_;
    largest_observed_ = sequence_number;
    return;
  }
  if (sequence_number > largest_observed_) {
    for (QuicPacketSequenceNumber i = 0;
         i < (sequence_number - largest_observed_ - 1); ++i) {
      packets_entropy_.push_back(std::make_pair(0, false));
    }
    packets_entropy_.push_back(std::make_pair(entropy_hash, true));
    largest_observed_ = sequence_number;
  } else {
    packets_entropy_[sequence_number - first_gap_] =
        std::make_pair(entropy_hash, true);
    AdvanceFirstGapAndGarbageCollectEntropyMap();
  }

  DVLOG(2) << "setting cumulative received entropy hash to: "
           << static_cast<int>(packets_entropy_hash_)
           << " updated with sequence number " << sequence_number
           << " entropy hash: " << static_cast<int>(entropy_hash);
}

void QuicReceivedPacketManager::EntropyTracker::SetCumulativeEntropyUpTo(
    QuicPacketSequenceNumber sequence_number,
    QuicPacketEntropyHash entropy_hash) {
  DCHECK_LE(sequence_number, largest_observed_);
  if (sequence_number < first_gap_) {
    DVLOG(1) << "Ignoring set entropy at:" << sequence_number
             << " less than first_gap_:" << first_gap_;
    return;
  }
  while (first_gap_ < sequence_number) {
    ++first_gap_;
    if (!packets_entropy_.empty()) {
      packets_entropy_.pop_front();
    }
  }
  // Compute the current entropy by XORing in all entropies received including
  // and since sequence_number.
  packets_entropy_hash_ = entropy_hash;
  for (ReceivedEntropyHashes::const_iterator it = packets_entropy_.begin();
           it != packets_entropy_.end(); ++it) {
    packets_entropy_hash_ ^= it->first;
  }

  // Garbage collect entries from the beginning of the map.
  AdvanceFirstGapAndGarbageCollectEntropyMap();
}

void QuicReceivedPacketManager::EntropyTracker::
AdvanceFirstGapAndGarbageCollectEntropyMap() {
  while (!packets_entropy_.empty() && packets_entropy_.front().second) {
    ++first_gap_;
    packets_entropy_.pop_front();
  }
}

QuicReceivedPacketManager::QuicReceivedPacketManager(QuicConnectionStats* stats)
    : peer_least_packet_awaiting_ack_(0),
      time_largest_observed_(QuicTime::Zero()),
      stats_(stats) {
  ack_frame_.largest_observed = 0;
  ack_frame_.entropy_hash = 0;
}

QuicReceivedPacketManager::~QuicReceivedPacketManager() {}

void QuicReceivedPacketManager::RecordPacketReceived(
    QuicByteCount bytes,
    const QuicPacketHeader& header,
    QuicTime receipt_time) {
  QuicPacketSequenceNumber sequence_number = header.packet_sequence_number;
  DCHECK(IsAwaitingPacket(sequence_number));

  InsertMissingPacketsBetween(
      &ack_frame_,
      max(ack_frame_.largest_observed + 1, peer_least_packet_awaiting_ack_),
      sequence_number);

  if (ack_frame_.largest_observed > sequence_number) {
    // We've gotten one of the out of order packets - remove it from our
    // "missing packets" list.
    DVLOG(1) << "Removing " << sequence_number << " from missing list";
    ack_frame_.missing_packets.erase(sequence_number);

    // Record how out of order stats.
    ++stats_->packets_reordered;
    stats_->max_sequence_reordering =
        max(stats_->max_sequence_reordering,
            ack_frame_.largest_observed - sequence_number);
    int64 reordering_time_us =
        receipt_time.Subtract(time_largest_observed_).ToMicroseconds();
    stats_->max_time_reordering_us = max(stats_->max_time_reordering_us,
                                         reordering_time_us);
  }
  if (sequence_number > ack_frame_.largest_observed) {
    ack_frame_.largest_observed = sequence_number;
    time_largest_observed_ = receipt_time;
  }
  entropy_tracker_.RecordPacketEntropyHash(sequence_number,
                                           header.entropy_hash);

  received_packet_times_.push_back(
      std::make_pair(sequence_number, receipt_time));

  ack_frame_.revived_packets.erase(sequence_number);
}

void QuicReceivedPacketManager::RecordPacketRevived(
    QuicPacketSequenceNumber sequence_number) {
  LOG_IF(DFATAL, !IsAwaitingPacket(sequence_number));
  ack_frame_.revived_packets.insert(sequence_number);
}

bool QuicReceivedPacketManager::IsMissing(
    QuicPacketSequenceNumber sequence_number) {
  return ContainsKey(ack_frame_.missing_packets, sequence_number);
}

bool QuicReceivedPacketManager::IsAwaitingPacket(
    QuicPacketSequenceNumber sequence_number) {
  return ::net::IsAwaitingPacket(ack_frame_, sequence_number);
}

namespace {
struct isTooLarge {
  explicit isTooLarge(QuicPacketSequenceNumber n) : largest_observed_(n) {}
  QuicPacketSequenceNumber largest_observed_;

  // Return true if the packet in p is too different from largest_observed_
  // to express.
  bool operator() (
      const std::pair<QuicPacketSequenceNumber, QuicTime>& p) const {
    return largest_observed_ - p.first >= numeric_limits<uint8>::max();
  }
};
}  // namespace

void QuicReceivedPacketManager::UpdateReceivedPacketInfo(
    QuicAckFrame* ack_frame, QuicTime approximate_now) {
  *ack_frame = ack_frame_;
  ack_frame->entropy_hash = EntropyHash(ack_frame_.largest_observed);

  if (time_largest_observed_ == QuicTime::Zero()) {
    // We have received no packets.
    ack_frame->delta_time_largest_observed = QuicTime::Delta::Infinite();
    return;
  }

  // Ensure the delta is zero if approximate now is "in the past".
  ack_frame->delta_time_largest_observed =
      approximate_now < time_largest_observed_ ?
          QuicTime::Delta::Zero() :
          approximate_now.Subtract(time_largest_observed_);

  // Remove all packets that are too far from largest_observed to express.
  received_packet_times_.remove_if(isTooLarge(ack_frame_.largest_observed));

  ack_frame->received_packet_times.clear();
  ack_frame->received_packet_times.swap(received_packet_times_);
}

QuicPacketEntropyHash QuicReceivedPacketManager::EntropyHash(
    QuicPacketSequenceNumber sequence_number) const {
  return entropy_tracker_.EntropyHash(sequence_number);
}

bool QuicReceivedPacketManager::DontWaitForPacketsBefore(
    QuicPacketSequenceNumber least_unacked) {
  ack_frame_.revived_packets.erase(
      ack_frame_.revived_packets.begin(),
      ack_frame_.revived_packets.lower_bound(least_unacked));
  size_t missing_packets_count = ack_frame_.missing_packets.size();
  ack_frame_.missing_packets.erase(
      ack_frame_.missing_packets.begin(),
      ack_frame_.missing_packets.lower_bound(least_unacked));
  return missing_packets_count != ack_frame_.missing_packets.size();
}

void QuicReceivedPacketManager::UpdatePacketInformationSentByPeer(
    const QuicStopWaitingFrame& stop_waiting) {
  // ValidateAck() should fail if peer_least_packet_awaiting_ack_ shrinks.
  DCHECK_LE(peer_least_packet_awaiting_ack_, stop_waiting.least_unacked);
  if (stop_waiting.least_unacked > peer_least_packet_awaiting_ack_) {
    bool missed_packets = DontWaitForPacketsBefore(stop_waiting.least_unacked);
    if (missed_packets) {
      DVLOG(1) << "Updating entropy hashed since we missed packets";
      // There were some missing packets that we won't ever get now. Recalculate
      // the received entropy hash.
      entropy_tracker_.SetCumulativeEntropyUpTo(stop_waiting.least_unacked,
                                                stop_waiting.entropy_hash);
    }
    peer_least_packet_awaiting_ack_ = stop_waiting.least_unacked;
  }
  DCHECK(ack_frame_.missing_packets.empty() ||
         *ack_frame_.missing_packets.begin() >=
             peer_least_packet_awaiting_ack_);
}

bool QuicReceivedPacketManager::HasNewMissingPackets() const {
  return !ack_frame_.missing_packets.empty() &&
      (ack_frame_.largest_observed -
       *ack_frame_.missing_packets.rbegin()) <= kMaxPacketsAfterNewMissing;
}

size_t QuicReceivedPacketManager::NumTrackedPackets() const {
  return entropy_tracker_.size();
}

}  // namespace net
