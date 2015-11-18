// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Accumulates frames for the next packet until more frames no longer fit or
// it's time to create a packet from them.  Also provides packet creation of
// FEC packets based on previously created packets.

#ifndef NET_QUIC_QUIC_PACKET_CREATOR_H_
#define NET_QUIC_QUIC_PACKET_CREATOR_H_

#include <string>
#include <utility>
#include <vector>

#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "net/quic/quic_fec_group.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_protocol.h"

namespace net {
namespace test {
class QuicPacketCreatorPeer;
}

class QuicRandom;
class QuicRandomBoolSource;

class NET_EXPORT_PRIVATE QuicPacketCreator {
 public:
  // QuicRandom* required for packet entropy.
  QuicPacketCreator(QuicConnectionId connection_id,
                    QuicFramer* framer,
                    QuicRandom* random_generator);

  ~QuicPacketCreator();

  // Turn on FEC protection for subsequently created packets. FEC should be
  // enabled first (max_packets_per_fec_group should be non-zero) for FEC
  // protection to start.
  void StartFecProtectingPackets();

  // Turn off FEC protection for subsequently created packets. If the creator
  // has any open FEC group, call will fail. It is the caller's responsibility
  // to flush out FEC packets in generation, and to verify with ShouldSendFec()
  // that there is no open FEC group.
  void StopFecProtectingPackets();

  // Checks if it's time to send an FEC packet.  |force_close| forces this to
  // return true if an FEC group is open.
  bool ShouldSendFec(bool force_close) const;

  // Resets (closes) the FEC group. This method should only be called on a
  // packet boundary.
  void ResetFecGroup();

  // Returns true if an FEC packet is under construction.
  bool IsFecGroupOpen() const;

  // Makes the framer not serialize the protocol version in sent packets.
  void StopSendingVersion();

  // Update the packet number length to use in future packets as soon as it
  // can be safely changed.
  void UpdatePacketNumberLength(QuicPacketNumber least_packet_awaited_by_peer,
                                QuicPacketCount max_packets_in_flight);

  // The overhead the framing will add for a packet with one frame.
  static size_t StreamFramePacketOverhead(
      QuicConnectionIdLength connection_id_length,
      bool include_version,
      QuicPacketNumberLength packet_number_length,
      QuicStreamOffset offset,
      InFecGroup is_in_fec_group);

  bool HasRoomForStreamFrame(QuicStreamId id, QuicStreamOffset offset) const;

  // Converts a raw payload to a frame which fits into the currently open
  // packet.  The payload begins at |iov_offset| into the |iov|.
  // Returns the number of bytes consumed from data.
  // If data is empty and fin is true, the expected behavior is to consume the
  // fin but return 0.  If any data is consumed, it will be copied into a
  // new buffer that |frame| will point to and will be stored in |buffer|.
  size_t CreateStreamFrame(QuicStreamId id,
                           QuicIOVector iov,
                           size_t iov_offset,
                           QuicStreamOffset offset,
                           bool fin,
                           QuicFrame* frame,
                           UniqueStreamBuffer* buffer);

  // Serializes all frames into a single packet. All frames must fit into a
  // single packet. Also, sets the entropy hash of the serialized packet to a
  // random bool and returns that value as a member of SerializedPacket.
  // Never returns a RetransmittableFrames in SerializedPacket.
  SerializedPacket SerializeAllFrames(const QuicFrames& frames,
                                      char* buffer,
                                      size_t buffer_len);

  // Re-serializes frames with the original packet's packet number length.
  // Used for retransmitting packets to ensure they aren't too long.
  // Caller must ensure that any open FEC group is closed before calling this
  // method.
  SerializedPacket ReserializeAllFrames(const RetransmittableFrames& frames,
                                        QuicPacketNumberLength original_length,
                                        char* buffer,
                                        size_t buffer_len);

  // Returns true if there are frames pending to be serialized.
  bool HasPendingFrames() const;

  // Returns true if there are retransmittable frames pending to be serialized.
  bool HasPendingRetransmittableFrames() const;

  // TODO(jri): Remove this method.
  // Returns whether FEC protection is currently enabled. Note: Enabled does not
  // mean that an FEC group is currently active; i.e., IsFecProtected() may
  // still return false.
  bool IsFecEnabled() const;

  // Returns true if subsequent packets will be FEC protected. Note: True does
  // not mean that an FEC packet is currently under construction; i.e.,
  // fec_group_.get() may still be nullptr, until MaybeStartFec() is called.
  bool IsFecProtected() const;

  // Returns the number of bytes which are available to be used by additional
  // frames in the packet.  Since stream frames are slightly smaller when they
  // are the last frame in a packet, this method will return a different
  // value than max_packet_size - PacketSize(), in this case.
  size_t BytesFree() const;

  // Returns the number of bytes that the packet will expand by if a new frame
  // is added to the packet. If the last frame was a stream frame, it will
  // expand slightly when a new frame is added, and this method returns the
  // amount of expected expansion. If the packet is in an FEC group, no
  // expansion happens and this method always returns zero.
  size_t ExpansionOnNewFrame() const;

  // Returns the number of bytes in the current packet, including the header,
  // if serialized with the current frames.  Adding a frame to the packet
  // may change the serialized length of existing frames, as per the comment
  // in BytesFree.
  size_t PacketSize() const;

  // TODO(jri): AddSavedFrame calls AddFrame, which only saves the frame
  // if it is a stream frame, not other types of frames. Fix this API;
  // add a AddNonSavedFrame method.
  // Adds |frame| to the packet creator's list of frames to be serialized.
  // Returns false if the frame doesn't fit into the current packet.
  bool AddSavedFrame(const QuicFrame& frame);

  // Identical to AddSavedFrame, but takes ownership of the buffer.
  bool AddSavedFrame(const QuicFrame& frame, UniqueStreamBuffer buffer);

  // Identical to AddSavedFrame, but takes ownership of the buffer, and allows
  // to cause the packet to be padded.
  bool AddPaddedSavedFrame(const QuicFrame& frame, UniqueStreamBuffer buffer);

  // Serializes all frames which have been added and adds any which should be
  // retransmitted to |retransmittable_frames| if it's not nullptr. All frames
  // must fit into a single packet. Sets the entropy hash of the serialized
  // packet to a random bool and returns that value as a member of
  // SerializedPacket. Also, sets |serialized_frames| in the SerializedPacket to
  // the corresponding RetransmittableFrames if any frames are to be
  // retransmitted.
  // Fails if |buffer_len| isn't long enough for the encrypted packet.
  SerializedPacket SerializePacket(char* encrypted_buffer, size_t buffer_len);

  // Packetize FEC data. All frames must fit into a single packet. Also, sets
  // the entropy hash of the serialized packet to a random bool and returns
  // that value as a member of SerializedPacket.
  // Fails if |buffer_len| isn't long enough for the encrypted packet.
  SerializedPacket SerializeFec(char* buffer, size_t buffer_len);

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
    encryption_level_ = level;
  }

  // packet number of the last created packet, or 0 if no packets have been
  // created.
  QuicPacketNumber packet_number() const { return packet_number_; }

  QuicConnectionIdLength connection_id_length() const {
    return connection_id_length_;
  }

  void set_connection_id_length(QuicConnectionIdLength length) {
    connection_id_length_ = length;
  }

  QuicByteCount max_packet_length() const {
    return max_packet_length_;
  }

  // Sets the encrypter to use for the encryption level and updates the max
  // plaintext size.
  void SetEncrypter(EncryptionLevel level, QuicEncrypter* encrypter);

  // Indicates whether the packet creator is in a state where it can change
  // current maximum packet length.
  bool CanSetMaxPacketLength() const;

  // Sets the maximum packet length.
  void SetMaxPacketLength(QuicByteCount length);

  // Returns current max number of packets covered by an FEC group.
  size_t max_packets_per_fec_group() const {
      return max_packets_per_fec_group_;
  }

  // Sets creator's max number of packets covered by an FEC group.
  // Note: While there are no constraints on |max_packets_per_fec_group|,
  // this setter enforces a min value of kLowestMaxPacketsPerFecGroup.
  // To turn off FEC protection, use StopFecProtectingPackets().
  void set_max_packets_per_fec_group(size_t max_packets_per_fec_group);

  // Returns the currently open FEC group's number.  Returns 0 when FEC is
  // disabled or no FEC group is open.
  QuicFecGroupNumber fec_group_number();

 private:
  friend class test::QuicPacketCreatorPeer;

  static bool ShouldRetransmit(const QuicFrame& frame);

  // Copies |length| bytes from iov starting at offset |iov_offset| into buffer.
  // |iov| must be at least iov_offset+length total length and buffer must be
  // at least |length| long.
  static void CopyToBuffer(QuicIOVector iov,
                           size_t iov_offset,
                           size_t length,
                           char* buffer);

  // Updates lengths and also starts an FEC group if FEC protection is on and
  // there is not already an FEC group open.
  InFecGroup MaybeUpdateLengthsAndStartFec();

  // Called when a data packet is constructed that is part of an FEC group.
  // |payload| is the non-encrypted FEC protected payload of the packet.
  void OnBuiltFecProtectedPayload(const QuicPacketHeader& header,
                                  base::StringPiece payload);

  void FillPacketHeader(QuicFecGroupNumber fec_group,
                        bool fec_flag,
                        QuicPacketHeader* header);

  // Allows a frame to be added without creating retransmittable frames.
  // Particularly useful for retransmits using SerializeAllFrames().
  bool AddFrame(const QuicFrame& frame,
                bool save_retransmittable_frames,
                bool needs_padding,
                UniqueStreamBuffer buffer);

  // Adds a padding frame to the current packet only if the current packet
  // contains a handshake message, and there is sufficient room to fit a
  // padding frame.
  void MaybeAddPadding();

  QuicConnectionId connection_id_;
  EncryptionLevel encryption_level_;
  QuicFramer* framer_;
  scoped_ptr<QuicRandomBoolSource> random_bool_source_;
  QuicPacketNumber packet_number_;
  // If true, any created packets will be FEC protected.
  bool should_fec_protect_;
  scoped_ptr<QuicFecGroup> fec_group_;
  // Controls whether protocol version should be included while serializing the
  // packet.
  bool send_version_in_packet_;
  // Maximum length including headers and encryption (UDP payload length.)
  QuicByteCount max_packet_length_;
  // 0 indicates FEC is disabled.
  size_t max_packets_per_fec_group_;
  // Length of connection_id to send over the wire.
  QuicConnectionIdLength connection_id_length_;
  // Staging variable to hold next packet number length. When sequence
  // number length is to be changed, this variable holds the new length until
  // a packet or FEC group boundary, when the creator's packet_number_length_
  // can be changed to this new value.
  QuicPacketNumberLength next_packet_number_length_;
  // packet number length for the current packet and for the current FEC group
  // when FEC is enabled. Mutable so PacketSize() can adjust it when the packet
  // is empty.
  mutable QuicPacketNumberLength packet_number_length_;
  // packet_size_ is mutable because it's just a cache of the current size.
  // packet_size should never be read directly, use PacketSize() instead.
  mutable size_t packet_size_;
  mutable size_t max_plaintext_size_;
  QuicFrames queued_frames_;
  scoped_ptr<RetransmittableFrames> queued_retransmittable_frames_;
  // If true, the packet will be padded up to |max_packet_length_|.
  bool needs_padding_;

  DISALLOW_COPY_AND_ASSIGN(QuicPacketCreator);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_PACKET_CREATOR_H_
