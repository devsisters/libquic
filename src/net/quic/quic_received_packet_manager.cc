// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_received_packet_manager.h"

#include <limits>
#include <utility>

#include "base/logging.h"
#include "base/stl_util.h"
#include "base/strings/stringprintf.h"
#include "net/base/linked_hash_map.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_bug_tracker.h"
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
    : packets_entropy_hash_(0), first_gap_(1), largest_observed_(0) {}

QuicReceivedPacketManager::EntropyTracker::~EntropyTracker() {}

QuicPacketEntropyHash QuicReceivedPacketManager::EntropyTracker::EntropyHash(
    QuicPacketNumber packet_number) const {
  DCHECK_LE(packet_number, largest_observed_);
  if (packet_number == largest_observed_) {
    return packets_entropy_hash_;
  }

  DCHECK_GE(packet_number, first_gap_);
  DCHECK_EQ(first_gap_ + packets_entropy_.size() - 1, largest_observed_);
  QuicPacketEntropyHash hash = packets_entropy_hash_;
  ReceivedEntropyHashes::const_reverse_iterator it = packets_entropy_.rbegin();
  for (QuicPacketNumber i = 0; i < (largest_observed_ - packet_number);
       ++i, ++it) {
    hash ^= it->first;
  }
  return hash;
}

void QuicReceivedPacketManager::EntropyTracker::RecordPacketEntropyHash(
    QuicPacketNumber packet_number,
    QuicPacketEntropyHash entropy_hash) {
  if (packet_number < first_gap_) {
    DVLOG(1) << "Ignoring received packet entropy for packet_number:"
             << packet_number
             << " less than largest_peer_packet_number:" << first_gap_;
    return;
  }
  // RecordPacketEntropyHash is only intended to be called once per packet.
  DCHECK(packet_number > largest_observed_ ||
         !packets_entropy_[packet_number - first_gap_].second);

  packets_entropy_hash_ ^= entropy_hash;

  // Optimize the typical case of no gaps.
  if (packet_number == largest_observed_ + 1 && packets_entropy_.empty()) {
    ++first_gap_;
    largest_observed_ = packet_number;
    return;
  }
  if (packet_number > largest_observed_) {
    for (QuicPacketNumber i = 0; i < (packet_number - largest_observed_ - 1);
         ++i) {
      packets_entropy_.push_back(std::make_pair(0, false));
    }
    packets_entropy_.push_back(std::make_pair(entropy_hash, true));
    largest_observed_ = packet_number;
  } else {
    packets_entropy_[packet_number - first_gap_] =
        std::make_pair(entropy_hash, true);
    AdvanceFirstGapAndGarbageCollectEntropyMap();
  }

  DVLOG(2) << "setting cumulative received entropy hash to: "
           << static_cast<int>(packets_entropy_hash_)
           << " updated with packet number " << packet_number
           << " entropy hash: " << static_cast<int>(entropy_hash);
}

void QuicReceivedPacketManager::EntropyTracker::SetCumulativeEntropyUpTo(
    QuicPacketNumber packet_number,
    QuicPacketEntropyHash entropy_hash) {
  DCHECK_LE(packet_number, largest_observed_);
  if (packet_number < first_gap_) {
    DVLOG(1) << "Ignoring set entropy at:" << packet_number
             << " less than first_gap_:" << first_gap_;
    return;
  }
  while (first_gap_ < packet_number) {
    ++first_gap_;
    if (!packets_entropy_.empty()) {
      packets_entropy_.pop_front();
    }
  }
  // Compute the current entropy by XORing in all entropies received including
  // and since packet_number.
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
      ack_frame_updated_(false),
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
  QuicPacketNumber packet_number = header.packet_number;
  DCHECK(IsAwaitingPacket(packet_number));
  ack_frame_updated_ = true;

  // Adds the range of packet numbers from max(largest observed + 1, least
  // awaiting ack) up to packet_number not including packet_number.
  ack_frame_.missing_packets.Add(
      max(ack_frame_.largest_observed + 1, peer_least_packet_awaiting_ack_),
      packet_number);

  if (ack_frame_.largest_observed > packet_number) {
    // We've gotten one of the out of order packets - remove it from our
    // "missing packets" list.
    DVLOG(1) << "Removing " << packet_number << " from missing list";
    ack_frame_.missing_packets.Remove(packet_number);

    // Record how out of order stats.
    ++stats_->packets_reordered;
    stats_->max_sequence_reordering =
        max(stats_->max_sequence_reordering,
            ack_frame_.largest_observed - packet_number);
    int64_t reordering_time_us =
        receipt_time.Subtract(time_largest_observed_).ToMicroseconds();
    stats_->max_time_reordering_us =
        max(stats_->max_time_reordering_us, reordering_time_us);
  }
  if (packet_number > ack_frame_.largest_observed) {
    ack_frame_.largest_observed = packet_number;
    time_largest_observed_ = receipt_time;
  }
  entropy_tracker_.RecordPacketEntropyHash(packet_number, header.entropy_hash);

  ack_frame_.received_packet_times.push_back(
      std::make_pair(packet_number, receipt_time));

  if (ack_frame_.latest_revived_packet == packet_number) {
    ack_frame_.latest_revived_packet = 0;
  }
}

void QuicReceivedPacketManager::RecordPacketRevived(
    QuicPacketNumber packet_number) {
  QUIC_BUG_IF(!IsAwaitingPacket(packet_number)) << base::StringPrintf(
      "Not waiting for %llu", static_cast<unsigned long long>(packet_number));
  ack_frame_updated_ = true;
  ack_frame_.latest_revived_packet = packet_number;
}

bool QuicReceivedPacketManager::IsMissing(QuicPacketNumber packet_number) {
  return ack_frame_.missing_packets.Contains(packet_number);
}

bool QuicReceivedPacketManager::IsAwaitingPacket(
    QuicPacketNumber packet_number) {
  return ::net::IsAwaitingPacket(ack_frame_, packet_number);
}

namespace {
struct isTooLarge {
  explicit isTooLarge(QuicPacketNumber n) : largest_observed_(n) {}
  QuicPacketNumber largest_observed_;

  // Return true if the packet in p is too different from largest_observed_
  // to express.
  bool operator()(const std::pair<QuicPacketNumber, QuicTime>& p) const {
    return largest_observed_ - p.first >= numeric_limits<uint8_t>::max();
  }
};
}  // namespace

void QuicReceivedPacketManager::UpdateReceivedPacketInfo(
    QuicAckFrame* ack_frame,
    QuicTime approximate_now) {
  ack_frame_updated_ = false;
  *ack_frame = ack_frame_;
  ack_frame->entropy_hash = EntropyHash(ack_frame_.largest_observed);

  if (time_largest_observed_ == QuicTime::Zero()) {
    // We have received no packets.
    ack_frame->ack_delay_time = QuicTime::Delta::Infinite();
    return;
  }

  // Ensure the delta is zero if approximate now is "in the past".
  ack_frame->ack_delay_time =
      approximate_now < time_largest_observed_
          ? QuicTime::Delta::Zero()
          : approximate_now.Subtract(time_largest_observed_);

  // Clear all packet times if any are too far from largest observed.
  // It's expected this is extremely rare.
  for (PacketTimeVector::iterator it = ack_frame_.received_packet_times.begin();
       it != ack_frame_.received_packet_times.end();) {
    if (ack_frame_.largest_observed - it->first >=
        numeric_limits<uint8_t>::max()) {
      it = ack_frame_.received_packet_times.erase(it);
    } else {
      ++it;
    }
  }

  // TODO(ianswett): Instead of transferring all the information over,
  // consider giving the QuicPacketGenerator a reference to this ack frame
  // and clear it afterwards.
  ack_frame->received_packet_times.clear();
  ack_frame->received_packet_times.swap(ack_frame_.received_packet_times);
}

QuicPacketEntropyHash QuicReceivedPacketManager::EntropyHash(
    QuicPacketNumber packet_number) const {
  return entropy_tracker_.EntropyHash(packet_number);
}

bool QuicReceivedPacketManager::DontWaitForPacketsBefore(
    QuicPacketNumber least_unacked) {
  if (ack_frame_.latest_revived_packet < least_unacked) {
    ack_frame_.latest_revived_packet = 0;
  }
  return ack_frame_.missing_packets.RemoveUpTo(least_unacked);
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
      // Ack frame gets updated because missing packets are updated because of
      // stop waiting frame.
      ack_frame_updated_ = true;
    }
    peer_least_packet_awaiting_ack_ = stop_waiting.least_unacked;
  }
  DCHECK(ack_frame_.missing_packets.Empty() ||
         ack_frame_.missing_packets.Min() >= peer_least_packet_awaiting_ack_);
}

bool QuicReceivedPacketManager::HasNewMissingPackets() const {
  return !ack_frame_.missing_packets.Empty() &&
         (ack_frame_.largest_observed - ack_frame_.missing_packets.Max()) <=
             kMaxPacketsAfterNewMissing;
}

size_t QuicReceivedPacketManager::NumTrackedPackets() const {
  return entropy_tracker_.size();
}

bool QuicReceivedPacketManager::ack_frame_updated() const {
  return ack_frame_updated_;
}

}  // namespace net
