// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Manages the packet entropy calculation for both sent and received packets
// for a connection.

#ifndef NET_QUIC_QUIC_RECEIVED_PACKET_MANAGER_H_
#define NET_QUIC_QUIC_RECEIVED_PACKET_MANAGER_H_

#include <stddef.h>

#include <deque>

#include "base/macros.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_protocol.h"

namespace net {

namespace test {
class EntropyTrackerPeer;
class QuicConnectionPeer;
class QuicReceivedPacketManagerPeer;
}  // namespace test

struct QuicConnectionStats;

// Records all received packets by a connection and tracks their entropy.
// Also calculates the correct entropy for the framer when it truncates an ack
// frame being serialized.
class NET_EXPORT_PRIVATE QuicReceivedPacketManager
    : public QuicReceivedEntropyHashCalculatorInterface {
 public:
  class NET_EXPORT_PRIVATE EntropyTracker {
   public:
    EntropyTracker();
    ~EntropyTracker();

    // Compute the XOR of the entropy of all received packets up to
    // and including packet_number.
    // Requires that either:
    //   packet_number == largest_observed_
    // or:
    //   packet_number > first_gap_ &&
    //   packet_number < largest_observed_ &&
    //   packet_number in packets_entropy_
    QuicPacketEntropyHash EntropyHash(QuicPacketNumber packet_number) const;

    // Record the received entropy hash against |packet_number|.
    // Performs garbage collection to advance first_gap_ if
    // packet_number == first_gap_.
    void RecordPacketEntropyHash(QuicPacketNumber packet_number,
                                 QuicPacketEntropyHash entropy_hash);

    // Sets the entropy hash up to but not including a packet number based
    // on the hash provided by a StopWaiting frame.  Clears older packet
    // entropy entries and performs garbage collection up to the first gap.
    void SetCumulativeEntropyUpTo(QuicPacketNumber packet_number,
                                  QuicPacketEntropyHash entropy_hash);

    size_t size() const { return packets_entropy_.size(); }

   private:
    friend class test::EntropyTrackerPeer;

    // A deque indexed by packet number storing the packet's hash and whether
    // a hash was recorded for that packet number.
    typedef std::deque<std::pair<QuicPacketEntropyHash, bool>>
        ReceivedEntropyHashes;

    // Recomputes first_gap_ and removes packets_entropy_ entries that are no
    // longer needed to compute EntropyHash.
    void AdvanceFirstGapAndGarbageCollectEntropyMap();

    // Map of received packet numbers to their corresponding entropy.
    // Stores an entry for every received packet whose packet_number is larger
    // than first_gap_.  Packets without the entropy bit set have an entropy
    // value of 0.
    ReceivedEntropyHashes packets_entropy_;

    // Cumulative hash of entropy of all received packets.
    QuicPacketEntropyHash packets_entropy_hash_;

    // packet number of the first packet that we do not know the entropy of.
    // If there are no gaps in the received packet sequence,
    // packets_entropy_ will be empty and first_gap_ will be equal to
    // 'largest_observed_ + 1' since that's the first packet for which
    // entropy is unknown.  If there are gaps, packets_entropy_ will
    // contain entries for all received packets with packet_number >
    // first_gap_.
    QuicPacketNumber first_gap_;

    // packet number of the largest observed packet.
    QuicPacketNumber largest_observed_;

    DISALLOW_COPY_AND_ASSIGN(EntropyTracker);
  };

  explicit QuicReceivedPacketManager(QuicConnectionStats* stats);
  ~QuicReceivedPacketManager() override;

  // Updates the internal state concerning which packets have been received.
  // bytes: the packet size in bytes including Quic Headers.
  // header: the packet header.
  // timestamp: the arrival time of the packet.
  virtual void RecordPacketReceived(QuicByteCount bytes,
                                    const QuicPacketHeader& header,
                                    QuicTime receipt_time);

  // Checks whether |packet_number| is missing and less than largest observed.
  virtual bool IsMissing(QuicPacketNumber packet_number);

  // Checks if we're still waiting for the packet with |packet_number|.
  virtual bool IsAwaitingPacket(QuicPacketNumber packet_number);

  // Retrieves a frame containing a QuicAckFrame.  The ack frame may not be
  // changed outside QuicReceivedPacketManager and must be serialized before
  // another packet is received, or it will change.
  const QuicFrame GetUpdatedAckFrame(QuicTime approximate_now);

  // QuicReceivedEntropyHashCalculatorInterface
  // Called by QuicFramer, when the outgoing ack gets truncated, to recalculate
  // the received entropy hash for the truncated ack frame.
  QuicPacketEntropyHash EntropyHash(
      QuicPacketNumber packet_number) const override;

  // Updates internal state based on |stop_waiting|.
  virtual void UpdatePacketInformationSentByPeer(
      const QuicStopWaitingFrame& stop_waiting);

  // Returns true if there are any missing packets.
  bool HasMissingPackets() const;

  // Returns true when there are new missing packets to be reported within 3
  // packets of the largest observed.
  virtual bool HasNewMissingPackets() const;

  // Returns the number of packets being tracked in the EntropyTracker.
  size_t NumTrackedPackets() const;

  // Sets the mode of packets set of ack_frame_ based on |version|.
  void SetVersion(QuicVersion version);

  QuicPacketNumber peer_least_packet_awaiting_ack() {
    return peer_least_packet_awaiting_ack_;
  }

  virtual bool ack_frame_updated() const;

  // For logging purposes.
  const QuicAckFrame& ack_frame() const { return ack_frame_; }

 private:
  friend class test::QuicConnectionPeer;
  friend class test::QuicReceivedPacketManagerPeer;

  // Deletes all missing packets before least unacked. The connection won't
  // process any packets with packet number before |least_unacked| that it
  // received after this call. Returns true if there were missing packets before
  // |least_unacked| unacked, false otherwise.
  bool DontWaitForPacketsBefore(QuicPacketNumber least_unacked);

  // Tracks entropy hashes of received packets.
  EntropyTracker entropy_tracker_;

  // Least packet number of the the packet sent by the peer for which it
  // hasn't received an ack.
  QuicPacketNumber peer_least_packet_awaiting_ack_;

  // Received packet information used to produce acks.
  QuicAckFrame ack_frame_;

  // True if |ack_frame_| has been updated since UpdateReceivedPacketInfo was
  // last called.
  bool ack_frame_updated_;

  // The time we received the largest_observed packet number, or zero if
  // no packet numbers have been received since UpdateReceivedPacketInfo.
  // Needed for calculating ack_delay_time.
  QuicTime time_largest_observed_;

  QuicConnectionStats* stats_;

  DISALLOW_COPY_AND_ASSIGN(QuicReceivedPacketManager);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_RECEIVED_PACKET_MANAGER_H_
