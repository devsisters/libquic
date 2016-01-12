// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Accumulates frames for the next packet until more frames no longer fit or
// it's time to create a packet from them.  Also provides packet creation of
// FEC packets based on previously created packets. If multipath enabled, only
// creates packets on one path at the same time. Currently, next packet number
// is tracked per-path.

#ifndef NET_QUIC_QUIC_PACKET_CREATOR_H_
#define NET_QUIC_QUIC_PACKET_CREATOR_H_

#include <stddef.h>

#include <string>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "net/quic/quic_fec_group.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_protocol.h"

using base::hash_map;

namespace net {
namespace test {
class QuicPacketCreatorPeer;
}

class QuicRandom;
class QuicRandomBoolSource;

class NET_EXPORT_PRIVATE QuicPacketCreator {
 public:
  // A delegate interface for further processing serialized packet.
  class NET_EXPORT_PRIVATE DelegateInterface {
   public:
    virtual ~DelegateInterface() {}
    // Called when a packet is serialized. Delegate does not take the ownership
    // of |serialized_packet|, but may take ownership of |packet.packet|
    // and |packet.retransmittable_frames|.  If it does so, they must be set
    // to nullptr.
    virtual void OnSerializedPacket(SerializedPacket* serialized_packet) = 0;
    virtual void CloseConnection(QuicErrorCode error, bool from_peer) = 0;
    // Called when current FEC group is reset (closed).
    virtual void OnResetFecGroup() = 0;
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

  // Checks if it's time to send an FEC packet.  |force_close| forces this to
  // return true if an FEC group is open.
  bool ShouldSendFec(bool force_close) const;

  // If ShouldSendFec returns true, serializes currently constructed FEC packet
  // and calls the delegate on the packet. Resets current FEC group if FEC
  // protection policy is FEC_ALARM_TRIGGER but |is_fec_timeout| is false.
  // Also tries to turn off FEC protection if should_fec_protect_next_packet is
  // false.
  void MaybeSendFecPacketAndCloseGroup(bool force_send_fec,
                                       bool is_fec_timeout);

  // Returns true if an FEC packet is under construction.
  bool IsFecGroupOpen() const;

  // Called after sending |packet_number| to determine whether an FEC alarm
  // should be set for sending out an FEC packet. Returns a positive and finite
  // timeout if an FEC alarm should be set, and infinite if no alarm should be
  // set.
  QuicTime::Delta GetFecTimeout(QuicPacketNumber packet_number);

  // Makes the framer not serialize the protocol version in sent packets.
  void StopSendingVersion();

  // Update the packet number length to use in future packets as soon as it
  // can be safely changed.
  // TODO(fayang): Directly set packet number length instead of compute it in
  // creator.
  void UpdatePacketNumberLength(QuicPacketNumber least_packet_awaited_by_peer,
                                QuicPacketCount max_packets_in_flight);

  // The overhead the framing will add for a packet with one frame.
  static size_t StreamFramePacketOverhead(
      QuicConnectionIdLength connection_id_length,
      bool include_version,
      QuicPacketNumberLength packet_number_length,
      QuicStreamOffset offset,
      InFecGroup is_in_fec_group);

  // Returns false and flushes all pending frames if current open packet is
  // full.
  // If current packet is not full, converts a raw payload into a stream frame
  // that fits into the open packet and adds it to the packet.
  // The payload begins at |iov_offset| into the |iov|.
  // Also tries to start FEC protection depends on |fec_protection|.
  bool ConsumeData(QuicStreamId id,
                   QuicIOVector iov,
                   size_t iov_offset,
                   QuicStreamOffset offset,
                   bool fin,
                   bool needs_padding,
                   QuicFrame* frame,
                   FecProtection fec_protection);

  // Returns true if current open packet can accommodate more stream frames of
  // stream |id| at |offset|, false otherwise.
  bool HasRoomForStreamFrame(QuicStreamId id, QuicStreamOffset offset) const;

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
  SerializedPacket ReserializeAllFrames(
      const RetransmittableFrames& frames,
      EncryptionLevel original_encryption_level,
      QuicPacketNumberLength original_length,
      char* buffer,
      size_t buffer_len);

  // Serializes all added frames into a single packet and invokes the delegate_
  // to further process the SerializedPacket.
  void Flush();

  // Returns true if there are frames pending to be serialized.
  bool HasPendingFrames() const;

  // Returns true if there are retransmittable frames pending to be serialized.
  bool HasPendingRetransmittableFrames() const;

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

  // Tries to add |frame| to the packet creator's list of frames to be
  // serialized. If the frame does not fit into the current packet, flushes the
  // packet and returns false.
  bool AddSavedFrame(const QuicFrame& frame);

  // Identical to AddSavedFrame, but allows the frame to be padded.
  bool AddPaddedSavedFrame(const QuicFrame& frame);

  // Adds |listener| to the next serialized packet and notifies the
  // std::listener
  // with |length| as the number of acked bytes.
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

  // Called when the congestion window has changed.
  void OnCongestionWindowChange(QuicPacketCount max_packets_in_flight);

  // Called when the RTT may have changed.
  void OnRttChange(QuicTime::Delta rtt);

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

  QuicByteCount max_packet_length() const { return max_packet_length_; }

  bool has_ack() const { return has_ack_; }

  bool has_stop_waiting() const { return has_stop_waiting_; }

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
  // calling this function. If |path_id| is different from current_path_, the
  // FEC packet (if exists) will be sent and next_packet_number_length_ is
  // recalculated.
  void SetCurrentPath(QuicPathId path_id,
                      QuicPacketNumber least_packet_awaited_by_peer,
                      QuicPacketCount max_packets_in_flight);

  // Returns current max number of packets covered by an FEC group.
  size_t max_packets_per_fec_group() const {
    return max_packets_per_fec_group_;
  }

  // Sets creator's max number of packets covered by an FEC group.
  // Note: While there are no constraints on |max_packets_per_fec_group|,
  // this setter enforces a min value of kLowestMaxPacketsPerFecGroup.
  // To turn off FEC protection, use StopFecProtectingPackets().
  void set_max_packets_per_fec_group(size_t max_packets_per_fec_group);

  FecSendPolicy fec_send_policy() { return fec_send_policy_; }

  void set_fec_send_policy(FecSendPolicy fec_send_policy) {
    fec_send_policy_ = fec_send_policy;
  }

  void set_rtt_multiplier_for_fec_timeout(
      float rtt_multiplier_for_fec_timeout) {
    rtt_multiplier_for_fec_timeout_ = rtt_multiplier_for_fec_timeout;
  }

  void set_debug_delegate(DebugDelegate* debug_delegate) {
    debug_delegate_ = debug_delegate;
  }

 private:
  friend class test::QuicPacketCreatorPeer;

  static bool ShouldRetransmit(const QuicFrame& frame);

  // Converts a raw payload to a frame which fits into the current open
  // packet.  The payload begins at |iov_offset| into the |iov|.
  // Returns the number of bytes consumed from data.
  // If data is empty and fin is true, the expected behavior is to consume the
  // fin but return 0.  If any data is consumed, it will be copied into a
  // new buffer that |frame| will point to and own.
  size_t CreateStreamFrame(QuicStreamId id,
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

  // Adds a |frame| if there is space and returns false and flushes all pending
  // frames if there isn't room. If |save_retransmittable_frames| is true,
  // saves the |frame| in the next SerializedPacket.
  bool AddFrame(const QuicFrame& frame, bool save_retransmittable_frames);

  // Adds a padding frame to the current packet only if the current packet
  // contains a handshake message, and there is sufficient room to fit a
  // padding frame.
  void MaybeAddPadding();

  // Serializes all frames which have been added and adds any which should be
  // retransmitted to queued_retransmittable_frames_ if it's not nullptr. All
  // frames must fit into a single packet. Sets the entropy hash of the
  // serialized packet to a random bool and returns that value as a member of
  // SerializedPacket. Also, sets |serialized_frames| in the SerializedPacket to
  // the corresponding RetransmittableFrames if any frames are to be
  // retransmitted.
  // Fails if |buffer_len| isn't long enough for the encrypted packet.
  SerializedPacket SerializePacket(char* encrypted_buffer, size_t buffer_len);

  // Called after a new SerialiedPacket is created to call the delegate's
  // OnSerializedPacket, reset state, and potentially flush FEC groups.
  void OnSerializedPacket(SerializedPacket* packet);

  // Turn on FEC protection for subsequent packets. If no FEC group is currently
  // open, this method flushes current open packet and then turns FEC on.
  void MaybeStartFecProtection();

  // Turn on FEC protection for subsequently created packets. FEC should be
  // enabled first (max_packets_per_fec_group should be non-zero) for FEC
  // protection to start.
  void StartFecProtectingPackets();

  // Turn off FEC protection for subsequently created packets. If the creator
  // has any open FEC group, call will fail. It is the caller's responsibility
  // to flush out FEC packets in generation, and to verify with ShouldSendFec()
  // that there is no open FEC group.
  void StopFecProtectingPackets();

  // Resets (closes) the FEC group. This method should only be called on a
  // packet boundary.
  void ResetFecGroup();

  // Packetize FEC data. All frames must fit into a single packet. Also, sets
  // the entropy hash of the serialized packet to a random bool and returns
  // that value as a member of SerializedPacket.
  // Fails if |buffer_len| isn't long enough for the encrypted packet.
  SerializedPacket SerializeFec(char* buffer, size_t buffer_len);

  // Does not own these delegates.
  DelegateInterface* delegate_;
  DebugDelegate* debug_delegate_;

  QuicConnectionId connection_id_;
  EncryptionLevel encryption_level_;
  // True if an ack is queued in queued_frames_.
  bool has_ack_;
  // True if a stop waiting frame is queued in queued_frames_.
  bool has_stop_waiting_;
  QuicFramer* framer_;
  scoped_ptr<QuicRandomBoolSource> random_bool_source_;
  // Map mapping path_id to last sent packet number on the path.
  hash_map<QuicPathId, QuicPacketNumber> multipath_packet_number_;
  // The path which current constructed packet will be sent on.
  QuicPathId current_path_;
  QuicBufferAllocator* const buffer_allocator_;
  QuicPacketNumber packet_number_;
  // True when creator is requested to turn on FEC protection. False otherwise.
  // There is a time difference between should_fec_protect_next_packet is
  // true/false and FEC is actually turned on/off (e.g., The creator may have an
  // open FEC group even if this variable is false).
  bool should_fec_protect_next_packet_;
  // If true, any created packets will be FEC protected.
  // TODO(fayang): Combine should_fec_protect_next_packet and fec_protect_ to
  // one variable.
  bool fec_protect_;
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
  // Stores ack std::listeners that should be attached to the next packet.
  std::list<AckListenerWrapper> ack_listeners_;

  // FEC policy that specifies when to send FEC packet.
  FecSendPolicy fec_send_policy_;
  // Timeout used for FEC alarm. Can be set to zero initially or if the SRTT has
  // not yet been set.
  QuicTime::Delta fec_timeout_;
  // The multiplication factor for FEC timeout based on RTT.
  // TODO(rtenneti): Delete this code after the 0.25 RTT FEC experiment.
  float rtt_multiplier_for_fec_timeout_;

  DISALLOW_COPY_AND_ASSIGN(QuicPacketCreator);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_PACKET_CREATOR_H_
