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
    QuicPacketSequenceNumber sequence_number) const {
  return packets_entropy_[sequence_number - map_offset_];
}

QuicPacketSequenceNumber
QuicSentEntropyManager::GetLargestPacketWithEntropy() const {
  return map_offset_ + packets_entropy_.size() - 1;
}

QuicPacketSequenceNumber
QuicSentEntropyManager::GetSmallestPacketWithEntropy() const {
  return map_offset_;
}

void QuicSentEntropyManager::UpdateCumulativeEntropy(
    QuicPacketSequenceNumber sequence_number,
    CumulativeEntropy* cumulative) const {
  while (cumulative->sequence_number < sequence_number) {
    ++cumulative->sequence_number;
    cumulative->entropy ^= GetPacketEntropy(cumulative->sequence_number);
  }
}

void QuicSentEntropyManager::RecordPacketEntropyHash(
    QuicPacketSequenceNumber sequence_number,
    QuicPacketEntropyHash entropy_hash) {
  if (!packets_entropy_.empty()) {
    // Ensure packets always are recorded in order.
    // Every packet's entropy is recorded, even if it's not sent, so there
    // are not sequence number gaps.
    DCHECK_EQ(GetLargestPacketWithEntropy() + 1, sequence_number);
  }
  packets_entropy_.push_back(entropy_hash);
  DVLOG(2) << "Recorded sequence number " << sequence_number
           << " with entropy hash: " << static_cast<int>(entropy_hash);
}

QuicPacketEntropyHash QuicSentEntropyManager::GetCumulativeEntropy(
    QuicPacketSequenceNumber sequence_number) {
  DCHECK_LE(last_cumulative_entropy_.sequence_number, sequence_number);
  DCHECK_GE(GetLargestPacketWithEntropy(), sequence_number);
  // First the entropy for largest_observed sequence number should be updated.
  UpdateCumulativeEntropy(sequence_number, &last_cumulative_entropy_);
  return last_cumulative_entropy_.entropy;
}

bool QuicSentEntropyManager::IsValidEntropy(
    QuicPacketSequenceNumber largest_observed,
    const SequenceNumberSet& missing_packets,
    QuicPacketEntropyHash entropy_hash) {
  DCHECK_GE(largest_observed, last_valid_entropy_.sequence_number);
  // Ensure the largest and smallest sequence numbers are in range.
  if (largest_observed > GetLargestPacketWithEntropy()) {
    return false;
  }
  if (!missing_packets.empty() &&
      *missing_packets.begin() < GetSmallestPacketWithEntropy()) {
    return false;
  }
  // First the entropy for largest_observed sequence number should be updated.
  UpdateCumulativeEntropy(largest_observed, &last_valid_entropy_);

  // Now XOR out all the missing entropies.
  QuicPacketEntropyHash expected_entropy_hash = last_valid_entropy_.entropy;
  for (SequenceNumberSet::const_iterator it = missing_packets.begin();
       it != missing_packets.end(); ++it) {
    expected_entropy_hash ^= GetPacketEntropy(*it);
  }
  DLOG_IF(WARNING, entropy_hash != expected_entropy_hash)
      << "Invalid entropy hash: " << static_cast<int>(entropy_hash)
      << " expected entropy hash: " << static_cast<int>(expected_entropy_hash);
  return entropy_hash == expected_entropy_hash;
}

void QuicSentEntropyManager::ClearEntropyBefore(
    QuicPacketSequenceNumber sequence_number) {
  // Don't discard entropy before updating the cumulative entropy used to
  // calculate EntropyHash and IsValidEntropy.
  if (last_cumulative_entropy_.sequence_number < sequence_number) {
    UpdateCumulativeEntropy(sequence_number, &last_cumulative_entropy_);
  }
  if (last_valid_entropy_.sequence_number < sequence_number) {
    UpdateCumulativeEntropy(sequence_number, &last_valid_entropy_);
  }
  while (map_offset_ < sequence_number) {
    packets_entropy_.pop_front();
    ++map_offset_;
  }
  DVLOG(2) << "Cleared entropy before: " << sequence_number;
}

}  // namespace net
