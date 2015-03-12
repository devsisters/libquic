// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Responsible for generating packets on behalf of a QuicConnection.
// Packets are serialized just-in-time.  Control frames are queued.
// Ack and Feedback frames will be requested from the Connection
// just-in-time.  When a packet needs to be sent, the Generator
// will serialize a packet and pass it to QuicConnection::SendOrQueuePacket()
//
// The Generator's mode of operation is controlled by two conditions:
//
// 1) Is the Delegate writable?
//
// If the Delegate is not writable, then no operations will cause
// a packet to be serialized.  In particular:
// * SetShouldSendAck will simply record that an ack is to be sent.
// * AddControlFrame will enqueue the control frame.
// * ConsumeData will do nothing.
//
// If the Delegate is writable, then the behavior depends on the second
// condition:
//
// 2) Is the Generator in batch mode?
//
// If the Generator is NOT in batch mode, then each call to a write
// operation will serialize one or more packets.  The contents will
// include any previous queued frames.  If an ack should be sent
// but has not been sent, then the Delegate will be asked to create
// an Ack frame which will then be included in the packet.  When
// the write call completes, the current packet will be serialized
// and sent to the Delegate, even if it is not full.
//
// If the Generator is in batch mode, then each write operation will
// add data to the "current" packet.  When the current packet becomes
// full, it will be serialized and sent to the packet.  When batch
// mode is ended via |FinishBatchOperations|, the current packet
// will be serialzied, even if it is not full.
//
// FEC behavior also depends on batch mode.  In batch mode, FEC packets
// will be sent after |max_packets_per_group| have been sent, as well
// as after batch operations are complete.  When not in batch mode,
// an FEC packet will be sent after each write call completes.
//
// TODO(rch): This behavior should probably be tuned.  When not in batch
// mode, we should probably set a timer so that several independent
// operations can be grouped into the same FEC group.
//
// When an FEC packet is generated, it will be send to the Delegate,
// even if the Delegate has become unwritable after handling the
// data packet immediately proceeding the FEC packet.

#ifndef NET_QUIC_QUIC_PACKET_GENERATOR_H_
#define NET_QUIC_QUIC_PACKET_GENERATOR_H_

#include <list>

#include "base/containers/hash_tables.h"
#include "net/quic/quic_ack_notifier.h"
#include "net/quic/quic_packet_creator.h"
#include "net/quic/quic_sent_packet_manager.h"
#include "net/quic/quic_types.h"

namespace net {

namespace test {
class QuicPacketGeneratorPeer;
}  // namespace test

class NET_EXPORT_PRIVATE QuicPacketGenerator {
 public:
  class NET_EXPORT_PRIVATE DelegateInterface {
   public:
    virtual ~DelegateInterface() {}
    virtual bool ShouldGeneratePacket(TransmissionType transmission_type,
                                      HasRetransmittableData retransmittable,
                                      IsHandshake handshake) = 0;
    virtual void PopulateAckFrame(QuicAckFrame* ack) = 0;
    virtual void PopulateStopWaitingFrame(
        QuicStopWaitingFrame* stop_waiting) = 0;
    // Takes ownership of |packet.packet| and |packet.retransmittable_frames|.
    virtual void OnSerializedPacket(const SerializedPacket& packet) = 0;
    virtual void CloseConnection(QuicErrorCode error, bool from_peer) = 0;
  };

  // Interface which gets callbacks from the QuicPacketGenerator at interesting
  // points.  Implementations must not mutate the state of the generator
  // as a result of these callbacks.
  class NET_EXPORT_PRIVATE DebugDelegate {
   public:
    virtual ~DebugDelegate() {}

    // Called when a frame has been added to the current packet.
    virtual void OnFrameAddedToPacket(const QuicFrame& frame) {}
  };

  QuicPacketGenerator(QuicConnectionId connection_id,
                      QuicFramer* framer,
                      QuicRandom* random_generator,
                      DelegateInterface* delegate);

  virtual ~QuicPacketGenerator();

  // Called by the connection in the event of the congestion window changing.
  void OnCongestionWindowChange(QuicPacketCount max_packets_in_flight);

  // Called by the connection when the RTT may have changed.
  void OnRttChange(QuicTime::Delta rtt);

  // Indicates that an ACK frame should be sent.
  // If |also_send_stop_waiting| is true, then it also indicates that a
  // STOP_WAITING frame should be sent as well.
  // The contents of the frame(s) will be generated via a call to the delegate
  // CreateAckFrame() when the packet is serialized.
  void SetShouldSendAck(bool also_send_stop_waiting);

  void AddControlFrame(const QuicFrame& frame);

  // Given some data, may consume part or all of it and pass it to the
  // packet creator to be serialized into packets. If not in batch
  // mode, these packets will also be sent during this call.
  // |delegate| (if not nullptr) will be informed once all packets sent as a
  // result of this call are ACKed by the peer.
  QuicConsumedData ConsumeData(QuicStreamId id,
                               const IOVector& data,
                               QuicStreamOffset offset,
                               bool fin,
                               FecProtection fec_protection,
                               QuicAckNotifier::DelegateInterface* delegate);

  // Indicates whether batch mode is currently enabled.
  bool InBatchMode();
  // Disables flushing.
  void StartBatchOperations();
  // Enables flushing and flushes queued data which can be sent.
  void FinishBatchOperations();

  // Flushes all queued frames, even frames which are not sendable.
  void FlushAllQueuedFrames();

  bool HasQueuedFrames() const;

  // Makes the framer not serialize the protocol version in sent packets.
  void StopSendingVersion();

  // Creates a version negotiation packet which supports |supported_versions|.
  // Caller owns the created  packet. Also, sets the entropy hash of the
  // serialized packet to a random bool and returns that value as a member of
  // SerializedPacket.
  QuicEncryptedPacket* SerializeVersionNegotiationPacket(
      const QuicVersionVector& supported_versions);


  // Re-serializes frames with the original packet's sequence number length.
  // Used for retransmitting packets to ensure they aren't too long.
  // Caller must ensure that any open FEC group is closed before calling this
  // method.
  SerializedPacket ReserializeAllFrames(
      const RetransmittableFrames& frames,
      QuicSequenceNumberLength original_length);

  // Update the sequence number length to use in future packets as soon as it
  // can be safely changed.
  void UpdateSequenceNumberLength(
      QuicPacketSequenceNumber least_packet_awaited_by_peer,
      QuicPacketCount max_packets_in_flight);

  // Set the minimum number of bytes for the connection id length;
  void SetConnectionIdLength(uint32 length);

  // Called when the FEC alarm fires.
  void OnFecTimeout();

  // Called after sending |sequence_number| to determine whether an FEC alarm
  // should be set for sending out an FEC packet. Returns a positive and finite
  // timeout if an FEC alarm should be set, and infinite if no alarm should be
  // set. OnFecTimeout should be called to send the FEC packet when the alarm
  // fires.
  QuicTime::Delta GetFecTimeout(QuicPacketSequenceNumber sequence_number);

  // Sets the encryption level that will be applied to new packets.
  void set_encryption_level(EncryptionLevel level);

  // Sequence number of the last created packet, or 0 if no packets have been
  // created.
  QuicPacketSequenceNumber sequence_number() const;

  QuicByteCount max_packet_length() const;

  void set_max_packet_length(QuicByteCount length);

  void set_debug_delegate(DebugDelegate* debug_delegate) {
    debug_delegate_ = debug_delegate;
  }

 private:
  friend class test::QuicPacketGeneratorPeer;

  // Turn on FEC protection for subsequent packets in the generator.
  // If no FEC group is currently open in the creator, this method flushes any
  // queued frames in the generator and in the creator, and it then turns FEC on
  // in the creator. This method may be called with an open FEC group in the
  // creator, in which case, only the generator's state is altered.
  void MaybeStartFecProtection();

  // Serializes and calls the delegate on an FEC packet if one was under
  // construction in the creator. When |force| is false, it relies on the
  // creator being ready to send an FEC packet, otherwise FEC packet is sent
  // as long as one is under construction in the creator. Also tries to turn
  // off FEC protection in the creator if it's off in the generator.
  void MaybeSendFecPacketAndCloseGroup(bool force);

  // Returns true if an FEC packet should be generated based on |force| and
  // current state of the generator and the creator.
  bool ShouldSendFecPacket(bool force);

  void SendQueuedFrames(bool flush);

  // Test to see if we have pending ack, or control frames.
  bool HasPendingFrames() const;
  // Test to see if the addition of a pending frame (which might be
  // retransmittable) would still allow the resulting packet to be sent now.
  bool CanSendWithNextPendingFrameAddition() const;
  // Add exactly one pending frame, preferring ack frames over control frames.
  bool AddNextPendingFrame();

  bool AddFrame(const QuicFrame& frame);

  void SerializeAndSendPacket();

  DelegateInterface* delegate_;
  DebugDelegate* debug_delegate_;

  QuicPacketCreator packet_creator_;
  QuicFrames queued_control_frames_;

  // True if batch mode is currently enabled.
  bool batch_mode_;

  // Timeout used for FEC alarm. Can be set to zero initially or if the SRTT has
  // not yet been set.
  QuicTime::Delta fec_timeout_;

  // True if FEC protection is on. The creator may have an open FEC group even
  // if this variable is false.
  bool should_fec_protect_;

  // Flags to indicate the need for just-in-time construction of a frame.
  bool should_send_ack_;
  bool should_send_stop_waiting_;
  // If we put a non-retransmittable frame (ack frame) in this packet, then we
  // have to hold a reference to it until we flush (and serialize it).
  // Retransmittable frames are referenced elsewhere so that they
  // can later be (optionally) retransmitted.
  QuicAckFrame pending_ack_frame_;
  QuicStopWaitingFrame pending_stop_waiting_frame_;
  // True if an ack or stop waiting frame is already queued, and should not be
  // re-added.
  bool ack_queued_;
  bool stop_waiting_queued_;

  // Stores notifiers that should be attached to the next serialized packet.
  std::list<QuicAckNotifier*> ack_notifiers_;

  DISALLOW_COPY_AND_ASSIGN(QuicPacketGenerator);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_PACKET_GENERATOR_H_
