// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Manages the packet entropy calculation for both sent and received packets
// for a connection.

#ifndef NET_QUIC_QUIC_SENT_ENTROPY_MANAGER_H_
#define NET_QUIC_QUIC_SENT_ENTROPY_MANAGER_H_

#include <deque>

#include "base/macros.h"
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

  // Record |entropy_hash| for sent packet corresponding to |packet_number|.
  void RecordPacketEntropyHash(QuicPacketNumber packet_number,
                               QuicPacketEntropyHash entropy_hash);

  // Retrieves the cumulative entropy up to |packet_number|.
  // Must always be called with a monotonically increasing |packet_number|.
  QuicPacketEntropyHash GetCumulativeEntropy(QuicPacketNumber packet_number);

  // Returns true if |entropy_hash| matches the expected sent entropy hash
  // up to |largest_observed| removing packet numbers from |missing_packets|.
  // Must always be called with a monotonically increasing |largest_observed|.
  bool IsValidEntropy(QuicPacketNumber largest_observed,
                      const PacketNumberQueue& missing_packets,
                      QuicPacketEntropyHash entropy_hash);

  // Removes unnecessary entries before |packet_number|.
  void ClearEntropyBefore(QuicPacketNumber packet_number);

 private:
  friend class test::QuicConnectionPeer;

  typedef std::deque<QuicPacketEntropyHash> SentEntropyMap;

  struct CumulativeEntropy {
    CumulativeEntropy() : packet_number(0), entropy(0) {}

    QuicPacketNumber packet_number;
    QuicPacketEntropyHash entropy;
  };

  // Convenience methods to get the largest and smallest packets with entropies.
  QuicPacketNumber GetLargestPacketWithEntropy() const;
  QuicPacketNumber GetSmallestPacketWithEntropy() const;
  // Convenience method to get the entropy hash for |packet_number|.
  QuicPacketEntropyHash GetPacketEntropy(QuicPacketNumber packet_number) const;

  // Update the cumulative entropy to |packet_number|.
  void UpdateCumulativeEntropy(QuicPacketNumber packet_number,
                               CumulativeEntropy* cumulative) const;

  // Maps packet numbers to the sent entropy hash for the packet number.
  SentEntropyMap packets_entropy_;
  QuicPacketNumber map_offset_;

  // Cache the cumulative entropy for IsValidEntropy.
  CumulativeEntropy last_valid_entropy_;

  // Cache the cumulative entropy for the packet number used by EntropyHash.
  CumulativeEntropy last_cumulative_entropy_;

  DISALLOW_COPY_AND_ASSIGN(QuicSentEntropyManager);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_SENT_ENTROPY_MANAGER_H_
