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

#ifndef NET_QUIC_QUIC_PACKET_GENERATOR_H_
#define NET_QUIC_QUIC_PACKET_GENERATOR_H_

#include <stddef.h>
#include <stdint.h>

#include <list>

#include "base/macros.h"
#include "net/quic/quic_packet_creator.h"
#include "net/quic/quic_sent_packet_manager.h"
#include "net/quic/quic_types.h"

namespace net {

namespace test {
class QuicPacketGeneratorPeer;
}  // namespace test

class NET_EXPORT_PRIVATE QuicPacketGenerator {
 public:
  class NET_EXPORT_PRIVATE DelegateInterface
      : public QuicPacketCreator::DelegateInterface {
   public:
    ~DelegateInterface() override {}
    // Consults delegate whether a packet should be generated.
    virtual bool ShouldGeneratePacket(HasRetransmittableData retransmittable,
                                      IsHandshake handshake) = 0;
    virtual const QuicFrame GetUpdatedAckFrame() = 0;
    virtual void PopulateStopWaitingFrame(
        QuicStopWaitingFrame* stop_waiting) = 0;
  };

  QuicPacketGenerator(QuicConnectionId connection_id,
                      QuicFramer* framer,
                      QuicRandom* random_generator,
                      QuicBufferAllocator* buffer_allocator,
                      DelegateInterface* delegate);

  ~QuicPacketGenerator();

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
                               QuicIOVector iov,
                               QuicStreamOffset offset,
                               bool fin,
                               QuicAckListenerInterface* listener);

  // Generates an MTU discovery packet of specified size.
  void GenerateMtuDiscoveryPacket(QuicByteCount target_mtu,
                                  QuicAckListenerInterface* listener);

  // Indicates whether batch mode is currently enabled.
  bool InBatchMode();
  // Disables flushing.
  void StartBatchOperations();
  // Enables flushing and flushes queued data which can be sent.
  void FinishBatchOperations();

  // Flushes all queued frames, even frames which are not sendable.
  void FlushAllQueuedFrames();

  bool HasQueuedFrames() const;

  // Whether the pending packet has no frames in it at the moment.
  bool IsPendingPacketEmpty() const;

  // Makes the framer not serialize the protocol version in sent packets.
  void StopSendingVersion();

  // SetDiversificationNonce sets the nonce that will be sent in each public
  // header of packets encrypted at the initial encryption level. Should only
  // be called by servers.
  void SetDiversificationNonce(const DiversificationNonce nonce);

  // Creates a version negotiation packet which supports |supported_versions|.
  // Caller owns the created  packet. Also, sets the entropy hash of the
  // serialized packet to a random bool and returns that value as a member of
  // SerializedPacket.
  QuicEncryptedPacket* SerializeVersionNegotiationPacket(
      const QuicVersionVector& supported_versions);

  // Re-serializes frames with the original packet's packet number length.
  // Used for retransmitting packets to ensure they aren't too long.
  void ReserializeAllFrames(const PendingRetransmission& retransmission,
                            char* buffer,
                            size_t buffer_len);

  // Update the packet number length to use in future packets as soon as it
  // can be safely changed.
  void UpdateSequenceNumberLength(QuicPacketNumber least_packet_awaited_by_peer,
                                  QuicPacketCount max_packets_in_flight);

  // Set the minimum number of bytes for the connection id length;
  void SetConnectionIdLength(uint32_t length);

  // Sets the encrypter to use for the encryption level.
  void SetEncrypter(EncryptionLevel level, QuicEncrypter* encrypter);

  // Sets the encryption level that will be applied to new packets.
  void set_encryption_level(EncryptionLevel level);

  // packet number of the last created packet, or 0 if no packets have been
  // created.
  QuicPacketNumber packet_number() const;

  // Returns the maximum length a current packet can actually have.
  QuicByteCount GetCurrentMaxPacketLength() const;

  // Set maximum packet length in the creator immediately.  May not be called
  // when there are frames queued in the creator.
  void SetMaxPacketLength(QuicByteCount length);

  // Sets |path_id| to be the path on which next packet is generated.
  void SetCurrentPath(QuicPathId path_id,
                      QuicPacketNumber least_packet_awaited_by_peer,
                      QuicPacketCount max_packets_in_flight);

  void set_debug_delegate(QuicPacketCreator::DebugDelegate* debug_delegate) {
    packet_creator_.set_debug_delegate(debug_delegate);
  }

  const QuicAckFrame& pending_ack_frame() const { return pending_ack_frame_; }

 private:
  friend class test::QuicPacketGeneratorPeer;

  void SendQueuedFrames(bool flush);

  // Test to see if we have pending ack, or control frames.
  bool HasPendingFrames() const;
  // Returns true if addition of a pending frame (which might be
  // retransmittable) would still allow the resulting packet to be sent now.
  bool CanSendWithNextPendingFrameAddition() const;
  // Add exactly one pending frame, preferring ack frames over control frames.
  // Returns true if a pending frame is successfully added.
  // Returns false and flushes current open packet if the pending frame cannot
  // fit into current open packet.
  bool AddNextPendingFrame();

  DelegateInterface* delegate_;

  QuicPacketCreator packet_creator_;
  QuicFrames queued_control_frames_;

  // True if batch mode is currently enabled.
  bool batch_mode_;

  // Flags to indicate the need for just-in-time construction of a frame.
  bool should_send_ack_;
  bool should_send_stop_waiting_;
  // If we put a non-retransmittable frame in this packet, then we have to hold
  // a reference to it until we flush (and serialize it). Retransmittable frames
  // are referenced elsewhere so that they can later be (optionally)
  // retransmitted.
  QuicAckFrame pending_ack_frame_;
  QuicStopWaitingFrame pending_stop_waiting_frame_;

  DISALLOW_COPY_AND_ASSIGN(QuicPacketGenerator);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_PACKET_GENERATOR_H_
