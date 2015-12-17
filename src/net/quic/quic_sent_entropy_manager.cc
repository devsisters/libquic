// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_sent_entropy_manager.h"

#include "base/logging.h"
#include "net/base/linked_hash_map.h"

using std::make_pair;
using std::max;
using std::min;

namespace net {

QuicSentEntropyManager::QuicSentEntropyManager() : map_offset_(1) {}

QuicSentEntropyManager::~QuicSentEntropyManager() {}

QuicPacketEntropyHash QuicSentEntropyManager::GetPacketEntropy(
    QuicPacketNumber packet_number) const {
  return packets_entropy_[packet_number - map_offset_];
}

QuicPacketNumber QuicSentEntropyManager::GetLargestPacketWithEntropy() const {
  return map_offset_ + packets_entropy_.size() - 1;
}

QuicPacketNumber QuicSentEntropyManager::GetSmallestPacketWithEntropy() const {
  return map_offset_;
}

void QuicSentEntropyManager::UpdateCumulativeEntropy(
    QuicPacketNumber packet_number,
    CumulativeEntropy* cumulative) const {
  while (cumulative->packet_number < packet_number) {
    ++cumulative->packet_number;
    cumulative->entropy ^= GetPacketEntropy(cumulative->packet_number);
  }
}

void QuicSentEntropyManager::RecordPacketEntropyHash(
    QuicPacketNumber packet_number,
    QuicPacketEntropyHash entropy_hash) {
  if (!packets_entropy_.empty()) {
    // Ensure packets always are recorded in order.
    // Every packet's entropy is recorded, even if it's not sent, so there
    // are not packet number gaps.
    DCHECK_EQ(GetLargestPacketWithEntropy() + 1, packet_number);
  }
  packets_entropy_.push_back(entropy_hash);
  DVLOG(2) << "Recorded packet number " << packet_number
           << " with entropy hash: " << static_cast<int>(entropy_hash);
}

QuicPacketEntropyHash QuicSentEntropyManager::GetCumulativeEntropy(
    QuicPacketNumber packet_number) {
  DCHECK_LE(last_cumulative_entropy_.packet_number, packet_number);
  DCHECK_GE(GetLargestPacketWithEntropy(), packet_number);
  // First the entropy for largest_observed packet number should be updated.
  UpdateCumulativeEntropy(packet_number, &last_cumulative_entropy_);
  return last_cumulative_entropy_.entropy;
}

bool QuicSentEntropyManager::IsValidEntropy(
    QuicPacketNumber largest_observed,
    const PacketNumberQueue& missing_packets,
    QuicPacketEntropyHash entropy_hash) {
  DCHECK_GE(largest_observed, last_valid_entropy_.packet_number);
  // Ensure the largest and smallest packet numbers are in range.
  if (largest_observed > GetLargestPacketWithEntropy()) {
    return false;
  }
  if (!missing_packets.Empty() &&
      missing_packets.Min() < GetSmallestPacketWithEntropy()) {
    return false;
  }
  // First the entropy for largest_observed packet number should be updated.
  UpdateCumulativeEntropy(largest_observed, &last_valid_entropy_);

  // Now XOR out all the missing entropies.
  QuicPacketEntropyHash expected_entropy_hash = last_valid_entropy_.entropy;
  for (QuicPacketNumber packet : missing_packets) {
    expected_entropy_hash ^= GetPacketEntropy(packet);
  }
  DLOG_IF(WARNING, entropy_hash != expected_entropy_hash)
      << "Invalid entropy hash: " << static_cast<int>(entropy_hash)
      << " expected entropy hash: " << static_cast<int>(expected_entropy_hash);
  return entropy_hash == expected_entropy_hash;
}

void QuicSentEntropyManager::ClearEntropyBefore(
    QuicPacketNumber packet_number) {
  // Don't discard entropy before updating the cumulative entropy used to
  // calculate EntropyHash and IsValidEntropy.
  if (last_cumulative_entropy_.packet_number < packet_number) {
    UpdateCumulativeEntropy(packet_number, &last_cumulative_entropy_);
  }
  if (last_valid_entropy_.packet_number < packet_number) {
    UpdateCumulativeEntropy(packet_number, &last_valid_entropy_);
  }
  while (map_offset_ < packet_number) {
    packets_entropy_.pop_front();
    ++map_offset_;
  }
  DVLOG(2) << "Cleared entropy before: " << packet_number;
}

}  // namespace net
