// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Manages the packet entropy calculation for both sent and received packets
// for a connection.

#ifndef NET_QUIC_QUIC_SENT_ENTROPY_MANAGER_H_
#define NET_QUIC_QUIC_SENT_ENTROPY_MANAGER_H_

#include <deque>

#include "net/base/linked_hash_map.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_protocol.h"

namespace net {

namespace test {
class QuicConnectionPeer;
}  // namespace test

// Records all sent packets by a connection to track the cumulative entropy of
// sent packets.  It is used by the connection to validate an ack
// frame sent by the peer as a preventive measure against the optimistic ack
// attack.
class NET_EXPORT_PRIVATE QuicSentEntropyManager {
 public:
  QuicSentEntropyManager();
  virtual ~QuicSentEntropyManager();

  // Record |entropy_hash| for sent packet corresponding to |sequence_number|.
  void RecordPacketEntropyHash(QuicPacketSequenceNumber sequence_number,
                               QuicPacketEntropyHash entropy_hash);

  // Retrieves the cumulative entropy up to |sequence_number|.
  // Must always be called with a monotonically increasing |sequence_number|.
  QuicPacketEntropyHash GetCumulativeEntropy(
      QuicPacketSequenceNumber sequence_number);

  // Returns true if |entropy_hash| matches the expected sent entropy hash
  // up to |largest_observed| removing sequence numbers from |missing_packets|.
  // Must always be called with a monotonically increasing |largest_observed|.
  bool IsValidEntropy(QuicPacketSequenceNumber largest_observed,
                      const SequenceNumberSet& missing_packets,
                      QuicPacketEntropyHash entropy_hash);

  // Removes unnecessary entries before |sequence_number|.
  void ClearEntropyBefore(QuicPacketSequenceNumber sequence_number);

 private:
  friend class test::QuicConnectionPeer;

  typedef std::deque<QuicPacketEntropyHash> SentEntropyMap;

  struct CumulativeEntropy {
    CumulativeEntropy() : sequence_number(0), entropy(0) {}

    QuicPacketSequenceNumber sequence_number;
    QuicPacketEntropyHash entropy;
  };

  // Convenience methods to get the largest and smallest packets with entropies.
  QuicPacketSequenceNumber GetLargestPacketWithEntropy() const;
  QuicPacketSequenceNumber GetSmallestPacketWithEntropy() const;
  // Convenience method to get the entropy hash for |sequence_number|.
  QuicPacketEntropyHash GetPacketEntropy(
      QuicPacketSequenceNumber sequence_number) const;

  // Update the cumulative entropy to |sequence_number|.
  void UpdateCumulativeEntropy(QuicPacketSequenceNumber sequence_number,
                               CumulativeEntropy* cumulative) const;

  // Maps sequence numbers to the sent entropy hash for the sequence number.
  SentEntropyMap packets_entropy_;
  QuicPacketSequenceNumber map_offset_;

  // Cache the cumulative entropy for IsValidEntropy.
  CumulativeEntropy last_valid_entropy_;

  // Cache the cumulative entropy for the sequence number used by EntropyHash.
  CumulativeEntropy last_cumulative_entropy_;

  DISALLOW_COPY_AND_ASSIGN(QuicSentEntropyManager);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_SENT_ENTROPY_MANAGER_H_
