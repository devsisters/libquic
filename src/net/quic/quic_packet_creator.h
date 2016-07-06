// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Accumulates frames for the next packet until more frames no longer fit or
// it's time to create a packet from them. If multipath enabled, only creates
// packets on one path at the same time. Currently, next packet number is
// tracked per-path.

#ifndef NET_QUIC_QUIC_PACKET_CREATOR_H_
#define NET_QUIC_QUIC_PACKET_CREATOR_H_

#include <stddef.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_protocol.h"

namespace net {
namespace test {
class QuicPacketCreatorPeer;
}

class QuicRandom;

class NET_EXPORT_PRIVATE QuicPacketCreator {
 public:
  // A delegate interface for further processing serialized packet.
  class NET_EXPORT_PRIVATE DelegateInterface
      : public QuicConnectionCloseDelegateInterface {
   public:
    ~DelegateInterface() override {}
    // Called when a packet is serialized. Delegate does not take the ownership
    // of |serialized_packet|, but takes ownership of any frames it removes
    // from |packet.retransmittable_frames|.
    virtual void OnSerializedPacket(SerializedPacket* serialized_packet) = 0;
  };

  // Interface which gets callbacks from the QuicPacketCreator at interesting
  // points.  Implementations must not mutate the state of the creator
  // as a result of these callbacks.
  class NET_EXPORT_PRIVATE DebugDelegate {
   public:
    virtual ~DebugDelegate() {}

    // Called when a frame has been added to the current packet.
    virtual void OnFrameAddedToPacket(const QuicFrame& frame) {}
  };

  // QuicRandom* required for packet entropy.
  QuicPacketCreator(QuicConnectionId connection_id,
                    QuicFramer* framer,
                    QuicRandom* random_generator,
                    QuicBufferAllocator* buffer_allocator,
                    DelegateInterface* delegate);

  ~QuicPacketCreator();

  // Makes the framer not serialize the protocol version in sent packets.
  void StopSendingVersion();

  // SetDiversificationNonce sets the nonce that will be sent in each public
  // header of packets encrypted at the initial encryption level. Should only
  // be called by servers.
  void SetDiversificationNonce(const DiversificationNonce nonce);

  // Update the packet number length to use in future packets as soon as it
  // can be safely changed.
  // TODO(fayang): Directly set packet number length instead of compute it in
  // creator.
  void UpdatePacketNumberLength(QuicPacketNumber least_packet_awaited_by_peer,
                                QuicPacketCount max_packets_in_flight);

  // The overhead the framing will add for a packet with one frame.
  static size_t StreamFramePacketOverhead(
      QuicVersion version,
      QuicConnectionIdLength connection_id_length,
      bool include_version,
      bool include_path_id,
      bool include_diversification_nonce,
      QuicPacketNumberLength packet_number_length,
      QuicStreamOffset offset);

  // Returns false and flushes all pending frames if current open packet is
  // full.
  // If current packet is not full, converts a raw payload into a stream frame
  // that fits into the open packet and adds it to the packet.
  // The payload begins at |iov_offset| into the |iov|.
  bool ConsumeData(QuicStreamId id,
                   QuicIOVector iov,
                   size_t iov_offset,
                   QuicStreamOffset offset,
                   bool fin,
                   bool needs_full_padding,
                   QuicFrame* frame);

  // Returns true if current open packet can accommodate more stream frames of
  // stream |id| at |offset|, false otherwise.
  bool HasRoomForStreamFrame(QuicStreamId id, QuicStreamOffset offset);

  // Re-serializes frames with the original packet's packet number length.
  // Used for retransmitting packets to ensure they aren't too long.
  void ReserializeAllFrames(const PendingRetransmission& retransmission,
                            char* buffer,
                            size_t buffer_len);

  // Serializes all added frames into a single packet and invokes the delegate_
  // to further process the SerializedPacket.
  void Flush();

  // Optimized method to create a QuicStreamFrame, serialize it, and encrypt it
  // into |encrypted_buffer|. Adds the QuicStreamFrame to the returned
  // SerializedPacket.  Sets |num_bytes_consumed| to the number of bytes
  // consumed to create the QuicStreamFrame.
  void CreateAndSerializeStreamFrame(QuicStreamId id,
                                     const QuicIOVector& iov,
                                     QuicStreamOffset iov_offset,
                                     QuicStreamOffset stream_offset,
                                     bool fin,
                                     QuicAckListenerInterface* listener,
                                     char* encrypted_buffer,
                                     size_t encrypted_buffer_len,
                                     size_t* num_bytes_consumed);

  // Returns true if there are frames pending to be serialized.
  bool HasPendingFrames() const;

  // Returns true if there are retransmittable frames pending to be serialized.
  bool HasPendingRetransmittableFrames() const;

  // Returns the number of bytes which are available to be used by additional
  // frames in the packet.  Since stream frames are slightly smaller when they
  // are the last frame in a packet, this method will return a different
  // value than max_packet_size - PacketSize(), in this case.
  size_t BytesFree();

  // Returns the number of bytes that the packet will expand by if a new frame
  // is added to the packet. If the last frame was a stream frame, it will
  // expand slightly when a new frame is added, and this method returns the
  // amount of expected expansion.
  size_t ExpansionOnNewFrame() const;

  // Returns the number of bytes in the current packet, including the header,
  // if serialized with the current frames.  Adding a frame to the packet
  // may change the serialized length of existing frames, as per the comment
  // in BytesFree.
  size_t PacketSize();

  // Tries to add |frame| to the packet creator's list of frames to be
  // serialized. If the frame does not fit into the current packet, flushes the
  // packet and returns false.
  bool AddSavedFrame(const QuicFrame& frame);

  // Identical to AddSavedFrame, but allows the frame to be padded.
  bool AddPaddedSavedFrame(const QuicFrame& frame);

  // Adds |listener| to the next serialized packet and notifies the
  // std::listener with |length| as the number of acked bytes.
  void AddAckListener(QuicAckListenerInterface* listener,
                      QuicPacketLength length);

  // Creates a version negotiation packet which supports |supported_versions|.
  // Caller owns the created  packet. Also, sets the entropy hash of the
  // serialized packet to a random bool and returns that value as a member of
  // SerializedPacket.
  QuicEncryptedPacket* SerializeVersionNegotiationPacket(
      const QuicVersionVector& supported_versions);

  // Returns a dummy packet that is valid but contains no useful information.
  static SerializedPacket NoPacket();

  // Sets the encryption level that will be applied to new packets.
  void set_encryption_level(EncryptionLevel level) {
    packet_.encryption_level = level;
  }

  // packet number of the last created packet, or 0 if no packets have been
  // created.
  QuicPacketNumber packet_number() const { return packet_.packet_number; }

  QuicConnectionIdLength connection_id_length() const {
    return connection_id_length_;
  }

  void set_connection_id_length(QuicConnectionIdLength length) {
    connection_id_length_ = length;
  }

  QuicByteCount max_packet_length() const { return max_packet_length_; }

  bool has_ack() const { return packet_.has_ack; }

  bool has_stop_waiting() const { return packet_.has_stop_waiting; }

  // Sets the encrypter to use for the encryption level and updates the max
  // plaintext size.
  void SetEncrypter(EncryptionLevel level, QuicEncrypter* encrypter);

  // Indicates whether the packet creator is in a state where it can change
  // current maximum packet length.
  bool CanSetMaxPacketLength() const;

  // Sets the maximum packet length.
  void SetMaxPacketLength(QuicByteCount length);

  // Sets the path on which subsequent packets will be created. It is the
  // caller's responsibility to guarantee no packet is under construction before
  // calling this function. If |path_id| is different from current_path_,
  // next_packet_number_length_ is recalculated.
  void SetCurrentPath(QuicPathId path_id,
                      QuicPacketNumber least_packet_awaited_by_peer,
                      QuicPacketCount max_packets_in_flight);

  void set_debug_delegate(DebugDelegate* debug_delegate) {
    debug_delegate_ = debug_delegate;
  }

 private:
  friend class test::QuicPacketCreatorPeer;

  // A QuicRandom wrapper that gets a bucket of entropy and distributes it
  // bit-by-bit. Replenishes the bucket as needed. Not thread-safe. Expose this
  // class if single bit randomness is needed elsewhere.
  class QuicRandomBoolSource {
   public:
    // random: Source of entropy. Not owned.
    explicit QuicRandomBoolSource(QuicRandom* random);

    ~QuicRandomBoolSource();

    // Returns the next random bit from the bucket.
    bool RandBool();

   private:
    // Source of entropy.
    QuicRandom* random_;
    // Stored random bits.
    uint64_t bit_bucket_;
    // The next available bit has "1" in the mask. Zero means empty bucket.
    uint64_t bit_mask_;

    DISALLOW_COPY_AND_ASSIGN(QuicRandomBoolSource);
  };

  static bool ShouldRetransmit(const QuicFrame& frame);

  // Converts a raw payload to a frame which fits into the current open
  // packet.  The payload begins at |iov_offset| into the |iov|.
  // If data is empty and fin is true, the expected behavior is to consume the
  // fin but return 0.  If any data is consumed, it will be copied into a
  // new buffer that |frame| will point to and own.
  void CreateStreamFrame(QuicStreamId id,
                         QuicIOVector iov,
                         size_t iov_offset,
                         QuicStreamOffset offset,
                         bool fin,
                         QuicFrame* frame);

  // Copies |length| bytes from iov starting at offset |iov_offset| into buffer.
  // |iov| must be at least iov_offset+length total length and buffer must be
  // at least |length| long.
  static void CopyToBuffer(QuicIOVector iov,
                           size_t iov_offset,
                           size_t length,
                           char* buffer);

  // Updates packet number length on packet boundary.
  void MaybeUpdatePacketNumberLength();

  void FillPacketHeader(QuicPacketHeader* header);

  // Adds a |frame| if there is space and returns false and flushes all pending
  // frames if there isn't room. If |save_retransmittable_frames| is true,
  // saves the |frame| in the next SerializedPacket.
  bool AddFrame(const QuicFrame& frame, bool save_retransmittable_frames);

  // Adds a padding frame to the current packet only if the current packet
  // contains a handshake message, and there is sufficient room to fit a
  // padding frame.
  void MaybeAddPadding();

  // Serializes all frames which have been added and adds any which should be
  // retransmitted to packet_.retransmittable_frames. All frames must fit into
  // a single packet. Sets the entropy hash of the serialized packet to a
  // random bool.
  // Fails if |buffer_len| isn't long enough for the encrypted packet.
  void SerializePacket(char* encrypted_buffer, size_t buffer_len);

  // Called after a new SerialiedPacket is created to call the delegate's
  // OnSerializedPacket and reset state.
  void OnSerializedPacket();

  // Clears all fields of packet_ that should be cleared between serializations.
  void ClearPacket();

  // Returns true if a diversification nonce should be included in the current
  // packet's public header.
  bool IncludeNonceInPublicHeader();

  // Does not own these delegates or the framer.
  DelegateInterface* delegate_;
  DebugDelegate* debug_delegate_;
  QuicFramer* framer_;

  QuicRandomBoolSource random_bool_source_;
  QuicBufferAllocator* const buffer_allocator_;

  // Controls whether version should be included while serializing the packet.
  bool send_version_in_packet_;
  // Controls whether path id should be included while serializing the packet.
  bool send_path_id_in_packet_;
  // Staging variable to hold next packet number length. When sequence
  // number length is to be changed, this variable holds the new length until
  // a packet boundary, when the creator's packet_number_length_ can be changed
  // to this new value.
  QuicPacketNumberLength next_packet_number_length_;
  // If true, then |nonce_for_public_header_| will be included in the public
  // header of all packets created at the initial encryption level.
  bool have_diversification_nonce_;
  DiversificationNonce diversification_nonce_;
  // Maximum length including headers and encryption (UDP payload length.)
  QuicByteCount max_packet_length_;
  size_t max_plaintext_size_;
  // Length of connection_id to send over the wire.
  QuicConnectionIdLength connection_id_length_;

  // Frames to be added to the next SerializedPacket
  QuicFrames queued_frames_;

  // packet_size should never be read directly, use PacketSize() instead.
  // TODO(ianswett): Move packet_size_ into SerializedPacket once
  // QuicEncryptedPacket has been flattened into SerializedPacket.
  size_t packet_size_;
  QuicConnectionId connection_id_;

  // Packet used to invoke OnSerializedPacket.
  SerializedPacket packet_;

  // Map mapping path_id to last sent packet number on the path.
  std::unordered_map<QuicPathId, QuicPacketNumber> multipath_packet_number_;

  DISALLOW_COPY_AND_ASSIGN(QuicPacketCreator);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_PACKET_CREATOR_H_
