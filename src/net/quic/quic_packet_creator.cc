// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_packet_creator.h"

#include <algorithm>

#include "base/logging.h"
#include "base/macros.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_data_writer.h"
#include "net/quic/quic_fec_group.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;
using std::make_pair;
using std::max;
using std::min;
using std::pair;
using std::vector;

namespace net {

namespace {

// Default max packets in an FEC group.
static const size_t kDefaultMaxPacketsPerFecGroup = 10;
// Lowest max packets in an FEC group.
static const size_t kLowestMaxPacketsPerFecGroup = 2;

// We want to put some space between a protected packet and the FEC packet to
// avoid losing them both within the same loss episode. On the other hand, we
// expect to be able to recover from any loss in about an RTT. We resolve this
// tradeoff by sending an FEC packet atmost half an RTT, or equivalently, half
// the max number of in-flight packets,  the first protected packet. Since we
// don't want to delay an FEC packet past half an RTT, we set the max FEC group
// size to be half the current congestion window.
const float kMaxPacketsInFlightMultiplierForFecGroupSize = 0.5;
const float kRttMultiplierForFecTimeout = 0.5;

// Minimum timeout for FEC alarm, set to half the minimum Tail Loss Probe
// timeout of 10ms.
const int64_t kMinFecTimeoutMs = 5u;

}  // namespace

// A QuicRandom wrapper that gets a bucket of entropy and distributes it
// bit-by-bit. Replenishes the bucket as needed. Not thread-safe. Expose this
// class if single bit randomness is needed elsewhere.
class QuicRandomBoolSource {
 public:
  // random: Source of entropy. Not owned.
  explicit QuicRandomBoolSource(QuicRandom* random)
      : random_(random), bit_bucket_(0), bit_mask_(0) {}

  ~QuicRandomBoolSource() {}

  // Returns the next random bit from the bucket.
  bool RandBool() {
    if (bit_mask_ == 0) {
      bit_bucket_ = random_->RandUint64();
      bit_mask_ = 1;
    }
    bool result = ((bit_bucket_ & bit_mask_) != 0);
    bit_mask_ <<= 1;
    return result;
  }

 private:
  // Source of entropy.
  QuicRandom* random_;
  // Stored random bits.
  uint64_t bit_bucket_;
  // The next available bit has "1" in the mask. Zero means empty bucket.
  uint64_t bit_mask_;

  DISALLOW_COPY_AND_ASSIGN(QuicRandomBoolSource);
};

QuicPacketCreator::QuicPacketCreator(QuicConnectionId connection_id,
                                     QuicFramer* framer,
                                     QuicRandom* random_generator,
                                     QuicBufferAllocator* buffer_allocator,
                                     DelegateInterface* delegate)
    : delegate_(delegate),
      debug_delegate_(nullptr),
      framer_(framer),
      random_bool_source_(new QuicRandomBoolSource(random_generator)),
      buffer_allocator_(buffer_allocator),
      send_version_in_packet_(framer->perspective() == Perspective::IS_CLIENT),
      send_path_id_in_packet_(false),
      next_packet_number_length_(PACKET_1BYTE_PACKET_NUMBER),
      max_packet_length_(0),
      connection_id_length_(PACKET_8BYTE_CONNECTION_ID),
      packet_size_(0),
      connection_id_(connection_id),
      packet_(kDefaultPathId,
              0,
              next_packet_number_length_,
              nullptr,
              0,
              0,
              false,
              false),
      should_fec_protect_next_packet_(false),
      fec_protect_(false),
      max_packets_per_fec_group_(kDefaultMaxPacketsPerFecGroup),
      fec_send_policy_(FEC_ANY_TRIGGER),
      fec_timeout_(QuicTime::Delta::Zero()),
      rtt_multiplier_for_fec_timeout_(kRttMultiplierForFecTimeout) {
  SetMaxPacketLength(kDefaultMaxPacketSize);
}

QuicPacketCreator::~QuicPacketCreator() {
  QuicUtils::DeleteFrames(&packet_.retransmittable_frames);
}

void QuicPacketCreator::OnBuiltFecProtectedPayload(
    const QuicPacketHeader& header,
    StringPiece payload) {
  if (fec_group_.get() != nullptr) {
    DCHECK_NE(0u, header.fec_group);
    fec_group_->Update(packet_.encryption_level, header, payload);
  }
}

void QuicPacketCreator::SetEncrypter(EncryptionLevel level,
                                     QuicEncrypter* encrypter) {
  framer_->SetEncrypter(level, encrypter);
  max_plaintext_size_ = framer_->GetMaxPlaintextSize(max_packet_length_);
}

bool QuicPacketCreator::CanSetMaxPacketLength() const {
  // |max_packet_length_| should not be changed mid-packet or mid-FEC group.
  return fec_group_.get() == nullptr && queued_frames_.empty();
}

void QuicPacketCreator::SetMaxPacketLength(QuicByteCount length) {
  DCHECK(CanSetMaxPacketLength());

  // Avoid recomputing |max_plaintext_size_| if the length does not actually
  // change.
  if (length == max_packet_length_) {
    return;
  }

  max_packet_length_ = length;
  max_plaintext_size_ = framer_->GetMaxPlaintextSize(max_packet_length_);
}

void QuicPacketCreator::set_max_packets_per_fec_group(
    size_t max_packets_per_fec_group) {
  max_packets_per_fec_group_ =
      max(kLowestMaxPacketsPerFecGroup, max_packets_per_fec_group);
  DCHECK_LT(0u, max_packets_per_fec_group_);
}

bool QuicPacketCreator::ShouldSendFec(bool force_close) const {
  return !HasPendingFrames() && fec_group_.get() != nullptr &&
         fec_group_->NumReceivedPackets() > 0 &&
         (force_close ||
          fec_group_->NumReceivedPackets() >= max_packets_per_fec_group_);
}

void QuicPacketCreator::ResetFecGroup() {
  if (HasPendingFrames()) {
    QUIC_BUG_IF(packet_size_ != 0)
        << "Cannot reset FEC group with pending frames.";
    return;
  }
  fec_group_.reset(nullptr);
}

bool QuicPacketCreator::IsFecGroupOpen() const {
  return fec_group_.get() != nullptr;
}

void QuicPacketCreator::StartFecProtectingPackets() {
  if (max_packets_per_fec_group_ == 0) {
    QUIC_BUG << "Cannot start FEC protection when FEC is not enabled.";
    return;
  }
  // TODO(jri): This currently requires that the generator flush out any
  // pending frames when FEC protection is turned on. If current packet can be
  // converted to an FEC protected packet, do it. This will require the
  // generator to check if the resulting expansion still allows the incoming
  // frame to be added to the packet.
  if (HasPendingFrames()) {
    QUIC_BUG << "Cannot start FEC protection with pending frames.";
    return;
  }
  DCHECK(!fec_protect_);
  fec_protect_ = true;
}

void QuicPacketCreator::StopFecProtectingPackets() {
  if (fec_group_.get() != nullptr) {
    QUIC_BUG << "Cannot stop FEC protection with open FEC group.";
    return;
  }
  DCHECK(fec_protect_);
  fec_protect_ = false;
}

InFecGroup QuicPacketCreator::MaybeUpdateLengthsAndStartFec() {
  if (fec_group_.get() != nullptr) {
    // Don't update any lengths when an FEC group is open, to ensure same
    // packet header size in all packets within a group.
    return IN_FEC_GROUP;
  }
  if (!queued_frames_.empty()) {
    // Don't change creator state if there are frames queued.
    return NOT_IN_FEC_GROUP;
  }

  // Update packet number length only on packet and FEC group boundaries.
  packet_.packet_number_length = next_packet_number_length_;

  if (!fec_protect_) {
    return NOT_IN_FEC_GROUP;
  }
  // Start a new FEC group since protection is on. Set the fec group number to
  // the packet number of the next packet.
  fec_group_.reset(new QuicFecGroup(packet_.packet_number + 1));
  return IN_FEC_GROUP;
}

// Stops serializing version of the protocol in packets sent after this call.
// A packet that is already open might send kQuicVersionSize bytes less than the
// maximum packet size if we stop sending version before it is serialized.
void QuicPacketCreator::StopSendingVersion() {
  DCHECK(send_version_in_packet_);
  send_version_in_packet_ = false;
  if (packet_size_ > 0) {
    DCHECK_LT(kQuicVersionSize, packet_size_);
    packet_size_ -= kQuicVersionSize;
  }
}

void QuicPacketCreator::UpdatePacketNumberLength(
    QuicPacketNumber least_packet_awaited_by_peer,
    QuicPacketCount max_packets_in_flight) {
  DCHECK_LE(least_packet_awaited_by_peer, packet_.packet_number + 1);
  // Since the packet creator will not change packet number length mid FEC
  // group, include the size of an FEC group to be safe.
  const QuicPacketNumber current_delta = max_packets_per_fec_group_ +
                                         packet_.packet_number + 1 -
                                         least_packet_awaited_by_peer;
  const uint64_t delta = max(current_delta, max_packets_in_flight);
  next_packet_number_length_ =
      QuicFramer::GetMinSequenceNumberLength(delta * 4);
}

bool QuicPacketCreator::ConsumeData(QuicStreamId id,
                                    QuicIOVector iov,
                                    size_t iov_offset,
                                    QuicStreamOffset offset,
                                    bool fin,
                                    bool needs_padding,
                                    QuicFrame* frame,
                                    FecProtection fec_protection) {
  if (!HasRoomForStreamFrame(id, offset)) {
    return false;
  }
  if (fec_protection == MUST_FEC_PROTECT) {
    should_fec_protect_next_packet_ = true;
    MaybeStartFecProtection();
  }
  CreateStreamFrame(id, iov, iov_offset, offset, fin, frame);
  if (!AddFrame(*frame, /*save_retransmittable_frames=*/true)) {
    // Fails if we try to write unencrypted stream data.
    delete frame->stream_frame;
    return false;
  }
  if (needs_padding) {
    packet_.needs_padding = true;
  }
  if (fec_protection == MUST_FEC_PROTECT &&
      iov_offset + frame->stream_frame->frame_length == iov.total_length) {
    // Turn off FEC protection when we're done writing protected data.
    DVLOG(1) << "Turning FEC protection OFF";
    should_fec_protect_next_packet_ = false;
  }
  return true;
}

bool QuicPacketCreator::HasRoomForStreamFrame(QuicStreamId id,
                                              QuicStreamOffset offset) {
  // TODO(jri): This is a simple safe decision for now, but make
  // is_in_fec_group a parameter. Same as with all public methods in
  // QuicPacketCreator.
  return BytesFree() >
         QuicFramer::GetMinStreamFrameSize(
             id, offset, true, fec_protect_ ? IN_FEC_GROUP : NOT_IN_FEC_GROUP);
}

// static
size_t QuicPacketCreator::StreamFramePacketOverhead(
    QuicConnectionIdLength connection_id_length,
    bool include_version,
    bool include_path_id,
    QuicPacketNumberLength packet_number_length,
    QuicStreamOffset offset,
    InFecGroup is_in_fec_group) {
  return GetPacketHeaderSize(connection_id_length, include_version,
                             include_path_id, packet_number_length,
                             is_in_fec_group) +
         // Assumes this is a stream with a single lone packet.
         QuicFramer::GetMinStreamFrameSize(1u, offset, true, is_in_fec_group);
}

size_t QuicPacketCreator::CreateStreamFrame(QuicStreamId id,
                                            QuicIOVector iov,
                                            size_t iov_offset,
                                            QuicStreamOffset offset,
                                            bool fin,
                                            QuicFrame* frame) {
  DCHECK_GT(max_packet_length_,
            StreamFramePacketOverhead(
                connection_id_length_, kIncludeVersion, kIncludePathId,
                PACKET_6BYTE_PACKET_NUMBER, offset, IN_FEC_GROUP));

  InFecGroup is_in_fec_group = MaybeUpdateLengthsAndStartFec();

  LOG_IF(DFATAL, !HasRoomForStreamFrame(id, offset))
      << "No room for Stream frame, BytesFree: " << BytesFree()
      << " MinStreamFrameSize: "
      << QuicFramer::GetMinStreamFrameSize(id, offset, true, is_in_fec_group);

  if (iov_offset == iov.total_length) {
    QUIC_BUG_IF(!fin) << "Creating a stream frame with no data or fin.";
    // Create a new packet for the fin, if necessary.
    *frame = QuicFrame(new QuicStreamFrame(id, true, offset, StringPiece()));
    return 0;
  }

  const size_t data_size = iov.total_length - iov_offset;
  size_t min_frame_size = QuicFramer::GetMinStreamFrameSize(
      id, offset, /* last_frame_in_packet= */ true, is_in_fec_group);
  size_t bytes_consumed = min<size_t>(BytesFree() - min_frame_size, data_size);

  bool set_fin = fin && bytes_consumed == data_size;  // Last frame.
  UniqueStreamBuffer buffer =
      NewStreamBuffer(buffer_allocator_, bytes_consumed);
  CopyToBuffer(iov, iov_offset, bytes_consumed, buffer.get());
  *frame = QuicFrame(new QuicStreamFrame(id, set_fin, offset, bytes_consumed,
                                         std::move(buffer)));
  return bytes_consumed;
}

// static
void QuicPacketCreator::CopyToBuffer(QuicIOVector iov,
                                     size_t iov_offset,
                                     size_t length,
                                     char* buffer) {
  int iovnum = 0;
  while (iovnum < iov.iov_count && iov_offset >= iov.iov[iovnum].iov_len) {
    iov_offset -= iov.iov[iovnum].iov_len;
    ++iovnum;
  }
  DCHECK_LE(iovnum, iov.iov_count);
  DCHECK_LE(iov_offset, iov.iov[iovnum].iov_len);
  if (iovnum >= iov.iov_count || length == 0) {
    return;
  }

  // Unroll the first iteration that handles iov_offset.
  const size_t iov_available = iov.iov[iovnum].iov_len - iov_offset;
  size_t copy_len = min(length, iov_available);

  // Try to prefetch the next iov if there is at least one more after the
  // current. Otherwise, it looks like an irregular access that the hardware
  // prefetcher won't speculatively prefetch. Only prefetch one iov because
  // generally, the iov_offset is not 0, input iov consists of 2K buffers and
  // the output buffer is ~1.4K.
  if (copy_len == iov_available && iovnum + 1 < iov.iov_count) {
    // TODO(ckrasic) - this is unused without prefetch()
    // char* next_base = static_cast<char*>(iov.iov[iovnum + 1].iov_base);
    // char* next_base = static_cast<char*>(iov.iov[iovnum + 1].iov_base);
    // Prefetch 2 cachelines worth of data to get the prefetcher started; leave
    // it to the hardware prefetcher after that.
    // TODO(ckrasic) - investigate what to do about prefetch directives.
    // prefetch(next_base, PREFETCH_HINT_T0);
    if (iov.iov[iovnum + 1].iov_len >= 64) {
      // TODO(ckrasic) - investigate what to do about prefetch directives.
      // prefetch(next_base + CACHELINE_SIZE, PREFETCH_HINT_T0);
    }
  }

  const char* src = static_cast<char*>(iov.iov[iovnum].iov_base) + iov_offset;
  while (true) {
    memcpy(buffer, src, copy_len);
    length -= copy_len;
    buffer += copy_len;
    if (length == 0 || ++iovnum >= iov.iov_count) {
      break;
    }
    src = static_cast<char*>(iov.iov[iovnum].iov_base);
    copy_len = min(length, iov.iov[iovnum].iov_len);
  }
  QUIC_BUG_IF(length > 0) << "Failed to copy entire length to buffer.";
}

void QuicPacketCreator::ReserializeAllFrames(
    const PendingRetransmission& retransmission,
    char* buffer,
    size_t buffer_len) {
  DCHECK(queued_frames_.empty());
  DCHECK(fec_group_.get() == nullptr);
  DCHECK(!packet_.needs_padding);
  QUIC_BUG_IF(retransmission.retransmittable_frames.empty())
      << "Attempt to serialize empty packet";
  const QuicPacketNumberLength saved_length = packet_.packet_number_length;
  const QuicPacketNumberLength saved_next_length = next_packet_number_length_;
  const bool saved_should_fec_protect = fec_protect_;
  const EncryptionLevel default_encryption_level = packet_.encryption_level;

  // Temporarily set the packet number length, stop FEC protection,
  // and change the encryption level.
  packet_.packet_number_length = retransmission.packet_number_length;
  next_packet_number_length_ = retransmission.packet_number_length;
  fec_protect_ = false;
  packet_.needs_padding = retransmission.needs_padding;
  // Only preserve the original encryption level if it's a handshake packet or
  // if we haven't gone forward secure.
  if (retransmission.has_crypto_handshake ||
      packet_.encryption_level != ENCRYPTION_FORWARD_SECURE) {
    packet_.encryption_level = retransmission.encryption_level;
  }

  // Serialize the packet and restore the FEC and packet number length state.
  for (const QuicFrame& frame : retransmission.retransmittable_frames) {
    bool success = AddFrame(frame, false);
    DCHECK(success);
  }
  SerializePacket(buffer, buffer_len);
  packet_.original_packet_number = retransmission.packet_number;
  packet_.transmission_type = retransmission.transmission_type;
  OnSerializedPacket();
  // Restore old values.
  packet_.packet_number_length = saved_length;
  next_packet_number_length_ = saved_next_length;
  fec_protect_ = saved_should_fec_protect;
  packet_.encryption_level = default_encryption_level;
}

void QuicPacketCreator::Flush() {
  if (!HasPendingFrames()) {
    return;
  }

  // TODO(rtenneti): Change the default 64 alignas value (used the default
  // value from CACHELINE_SIZE).
  ALIGNAS(64) char seralized_packet_buffer[kMaxPacketSize];
  SerializePacket(seralized_packet_buffer, kMaxPacketSize);
  OnSerializedPacket();
}

void QuicPacketCreator::OnSerializedPacket() {
  if (packet_.encrypted_buffer == nullptr) {
    QUIC_BUG << "Failed to SerializePacket. fec_policy:" << fec_send_policy()
             << " should_fec_protect_:" << should_fec_protect_next_packet_;
    delegate_->OnUnrecoverableError(QUIC_FAILED_TO_SERIALIZE_PACKET,
                                    ConnectionCloseSource::FROM_SELF);
    return;
  }

  delegate_->OnSerializedPacket(&packet_);
  ClearPacket();
  MaybeSendFecPacketAndCloseGroup(/*force_send_fec=*/false,
                                  /*is_fec_timeout=*/false);
  // Maximum packet size may be only enacted while no packet is currently being
  // constructed, so here we have a good opportunity to actually change it.
  if (CanSetMaxPacketLength()) {
    SetMaxPacketLength(max_packet_length_);
  }
}

void QuicPacketCreator::ClearPacket() {
  packet_.has_ack = false;
  packet_.has_stop_waiting = false;
  packet_.has_crypto_handshake = NOT_HANDSHAKE;
  packet_.needs_padding = false;
  packet_.is_fec_packet = false;
  packet_.original_packet_number = 0;
  packet_.transmission_type = NOT_RETRANSMISSION;
  packet_.encrypted_buffer = nullptr;
  packet_.encrypted_length = 0;
  DCHECK(packet_.retransmittable_frames.empty());
  packet_.listeners.clear();
}

bool QuicPacketCreator::HasPendingFrames() const {
  return !queued_frames_.empty();
}

bool QuicPacketCreator::HasPendingRetransmittableFrames() const {
  return !packet_.retransmittable_frames.empty();
}

size_t QuicPacketCreator::ExpansionOnNewFrame() const {
  // If packet is FEC protected, there's no expansion.
  if (fec_protect_) {
    return 0;
  }
  // If the last frame in the packet is a stream frame, then it will expand to
  // include the stream_length field when a new frame is added.
  bool has_trailing_stream_frame =
      !queued_frames_.empty() && queued_frames_.back().type == STREAM_FRAME;
  return has_trailing_stream_frame ? kQuicStreamPayloadLengthSize : 0;
}

size_t QuicPacketCreator::BytesFree() {
  DCHECK_GE(max_plaintext_size_, PacketSize());
  return max_plaintext_size_ -
         min(max_plaintext_size_, PacketSize() + ExpansionOnNewFrame());
}

size_t QuicPacketCreator::PacketSize() {
  if (!queued_frames_.empty()) {
    return packet_size_;
  }
  if (fec_group_.get() == nullptr) {
    // Update packet number length on packet and FEC boundary.
    packet_.packet_number_length = next_packet_number_length_;
  }
  packet_size_ =
      GetPacketHeaderSize(connection_id_length_, send_version_in_packet_,
                          send_path_id_in_packet_, packet_.packet_number_length,
                          fec_protect_ ? IN_FEC_GROUP : NOT_IN_FEC_GROUP);
  return packet_size_;
}

bool QuicPacketCreator::AddSavedFrame(const QuicFrame& frame) {
  return AddFrame(frame, /*save_retransmittable_frames=*/true);
}

bool QuicPacketCreator::AddPaddedSavedFrame(const QuicFrame& frame) {
  if (AddFrame(frame, /*save_retransmittable_frames=*/true)) {
    packet_.needs_padding = true;
    return true;
  }
  return false;
}

void QuicPacketCreator::AddAckListener(QuicAckListenerInterface* listener,
                                       QuicPacketLength length) {
  DCHECK(!queued_frames_.empty());
  packet_.listeners.emplace_back(listener, length);
}

void QuicPacketCreator::SerializePacket(char* encrypted_buffer,
                                        size_t encrypted_buffer_len) {
  DCHECK_LT(0u, encrypted_buffer_len);
  QUIC_BUG_IF(queued_frames_.empty()) << "Attempt to serialize empty packet";
  if (fec_group_.get() != nullptr) {
    DCHECK_GE(packet_.packet_number + 1, fec_group_->FecGroupNumber());
  }
  QuicPacketHeader header;
  // FillPacketHeader increments packet_number_.
  FillPacketHeader(fec_group_ != nullptr ? fec_group_->FecGroupNumber() : 0,
                   false, &header);

  MaybeAddPadding();

  DCHECK_GE(max_plaintext_size_, packet_size_);
  // ACK Frames will be truncated due to length only if they're the only frame
  // in the packet, and if packet_size_ was set to max_plaintext_size_. If
  // truncation due to length occurred, then GetSerializedFrameLength will have
  // returned all bytes free.
  bool possibly_truncated_by_length = packet_size_ == max_plaintext_size_ &&
                                      queued_frames_.size() == 1 &&
                                      queued_frames_.back().type == ACK_FRAME;
  // Use the packet_size_ instead of the buffer size to ensure smaller
  // packet sizes are properly used.
  size_t length = framer_->BuildDataPacket(header, queued_frames_,
                                           encrypted_buffer, packet_size_);
  if (length == 0) {
    QUIC_BUG << "Failed to serialize " << queued_frames_.size() << " frames.";
    return;
  }

  // TODO(ianswett) Consider replacing QuicPacket with something else, since
  // it's only used to provide convenience methods to FEC and encryption.
  QuicPacket packet(
      encrypted_buffer, length,
      /* owns_buffer */ false, header.public_header.connection_id_length,
      header.public_header.version_flag, header.public_header.multipath_flag,
      header.public_header.packet_number_length);
  OnBuiltFecProtectedPayload(header, packet.FecProtectedData());

  // Because of possible truncation, we can't be confident that our
  // packet size calculation worked correctly.
  if (!possibly_truncated_by_length) {
    DCHECK_EQ(packet_size_, length);
  }
  // Immediately encrypt the packet, to ensure we don't encrypt the same
  // packet number multiple times.
  size_t encrypted_length = framer_->EncryptPayload(
      packet_.encryption_level, packet_.path_id, packet_.packet_number, packet,
      encrypted_buffer, encrypted_buffer_len);
  if (encrypted_length == 0) {
    QUIC_BUG << "Failed to encrypt packet number " << packet_.packet_number;
    return;
  }

  packet_size_ = 0;
  queued_frames_.clear();
  packet_.entropy_hash = QuicFramer::GetPacketEntropyHash(header);
  packet_.encrypted_buffer = encrypted_buffer;
  packet_.encrypted_length = encrypted_length;
}

void QuicPacketCreator::SerializeFec(char* buffer, size_t buffer_len) {
  DCHECK_LT(0u, buffer_len);
  if (fec_group_.get() == nullptr || fec_group_->NumReceivedPackets() <= 0) {
    QUIC_BUG << "SerializeFEC called but no group or zero packets in group.";
    return;
  }
  if (FLAGS_quic_no_unencrypted_fec &&
      packet_.encryption_level == ENCRYPTION_NONE) {
    QUIC_BUG << "SerializeFEC must be called with encryption.";
    delegate_->OnUnrecoverableError(QUIC_UNENCRYPTED_FEC_DATA,
                                    ConnectionCloseSource::FROM_SELF);
    return;
  }
  DCHECK_EQ(0u, queued_frames_.size());
  QuicPacketHeader header;
  FillPacketHeader(fec_group_->FecGroupNumber(), true, &header);
  scoped_ptr<QuicPacket> packet(
      framer_->BuildFecPacket(header, fec_group_->PayloadParity()));
  fec_group_.reset(nullptr);
  packet_size_ = 0;
  QUIC_BUG_IF(packet == nullptr) << "Failed to serialize fec packet for group:"
                                 << fec_group_->FecGroupNumber();
  DCHECK_GE(max_packet_length_, packet->length());
  // Immediately encrypt the packet, to ensure we don't encrypt the same packet
  // packet number multiple times.
  size_t encrypted_length = framer_->EncryptPayload(
      packet_.encryption_level, packet_.path_id, packet_.packet_number, *packet,
      buffer, buffer_len);
  if (encrypted_length == 0) {
    QUIC_BUG << "Failed to encrypt packet number " << packet_.packet_number;
    return;
  }
  packet_.entropy_hash = QuicFramer::GetPacketEntropyHash(header);
  packet_.encrypted_buffer = buffer;
  packet_.encrypted_length = encrypted_length;
  packet_.is_fec_packet = true;
}

QuicEncryptedPacket* QuicPacketCreator::SerializeVersionNegotiationPacket(
    const QuicVersionVector& supported_versions) {
  DCHECK_EQ(Perspective::IS_SERVER, framer_->perspective());
  QuicEncryptedPacket* encrypted = QuicFramer::BuildVersionNegotiationPacket(
      connection_id_, supported_versions);
  DCHECK(encrypted);
  DCHECK_GE(max_packet_length_, encrypted->length());
  return encrypted;
}

// TODO(jri): Make this a public method of framer?
SerializedPacket QuicPacketCreator::NoPacket() {
  return SerializedPacket(kInvalidPathId, 0, PACKET_1BYTE_PACKET_NUMBER,
                          nullptr, 0, 0, false, false);
}

void QuicPacketCreator::FillPacketHeader(QuicFecGroupNumber fec_group,
                                         bool fec_flag,
                                         QuicPacketHeader* header) {
  header->public_header.connection_id = connection_id_;
  header->public_header.connection_id_length = connection_id_length_;
  header->public_header.multipath_flag = send_path_id_in_packet_;
  header->public_header.reset_flag = false;
  header->public_header.version_flag = send_version_in_packet_;
  header->fec_flag = fec_flag;
  header->path_id = packet_.path_id;
  header->packet_number = ++packet_.packet_number;
  header->public_header.packet_number_length = packet_.packet_number_length;
  header->entropy_flag = random_bool_source_->RandBool();
  header->is_in_fec_group = fec_group == 0 ? NOT_IN_FEC_GROUP : IN_FEC_GROUP;
  header->fec_group = fec_group;
}

bool QuicPacketCreator::ShouldRetransmit(const QuicFrame& frame) {
  switch (frame.type) {
    case ACK_FRAME:
    case PADDING_FRAME:
    case STOP_WAITING_FRAME:
    case MTU_DISCOVERY_FRAME:
      return false;
    default:
      return true;
  }
}

bool QuicPacketCreator::AddFrame(const QuicFrame& frame,
                                 bool save_retransmittable_frames) {
  DVLOG(1) << "Adding frame: " << frame;
  if (FLAGS_quic_never_write_unencrypted_data && frame.type == STREAM_FRAME &&
      frame.stream_frame->stream_id != kCryptoStreamId &&
      packet_.encryption_level == ENCRYPTION_NONE) {
    QUIC_BUG << "Cannot send stream data without encryption.";
    delegate_->OnUnrecoverableError(QUIC_UNENCRYPTED_STREAM_DATA,
                                    ConnectionCloseSource::FROM_SELF);
    return false;
  }
  InFecGroup is_in_fec_group = MaybeUpdateLengthsAndStartFec();

  size_t frame_len = framer_->GetSerializedFrameLength(
      frame, BytesFree(), queued_frames_.empty(), true, is_in_fec_group,
      packet_.packet_number_length);
  if (frame_len == 0) {
    // Current open packet is full.
    Flush();
    return false;
  }
  DCHECK_LT(0u, packet_size_);
  packet_size_ += ExpansionOnNewFrame() + frame_len;

  if (save_retransmittable_frames && ShouldRetransmit(frame)) {
    if (packet_.retransmittable_frames.empty()) {
      packet_.retransmittable_frames.reserve(2);
    }
    packet_.retransmittable_frames.push_back(frame);
    queued_frames_.push_back(frame);
    if (frame.type == STREAM_FRAME &&
        frame.stream_frame->stream_id == kCryptoStreamId) {
      packet_.has_crypto_handshake = IS_HANDSHAKE;
    }
  } else {
    queued_frames_.push_back(frame);
  }

  if (frame.type == ACK_FRAME) {
    packet_.has_ack = true;
  }
  if (frame.type == STOP_WAITING_FRAME) {
    packet_.has_stop_waiting = true;
  }
  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnFrameAddedToPacket(frame);
  }

  return true;
}

void QuicPacketCreator::MaybeAddPadding() {
  if (!packet_.needs_padding) {
    return;
  }

  if (BytesFree() == 0) {
    // Don't pad full packets.
    return;
  }

  bool success = AddFrame(QuicFrame(QuicPaddingFrame()), false);
  DCHECK(success);
}

void QuicPacketCreator::MaybeStartFecProtection() {
  if (max_packets_per_fec_group_ == 0 || fec_protect_) {
    // Do not start FEC protection when FEC protection is not enabled or FEC
    // protection is already on.
    return;
  }
  DVLOG(1) << "Turning FEC protection ON";
  // Flush current open packet.
  Flush();

  StartFecProtectingPackets();
  DCHECK(fec_protect_);
}

void QuicPacketCreator::MaybeSendFecPacketAndCloseGroup(bool force_send_fec,
                                                        bool is_fec_timeout) {
  if (ShouldSendFec(force_send_fec)) {
    if ((FLAGS_quic_no_unencrypted_fec &&
         packet_.encryption_level == ENCRYPTION_NONE) ||
        (fec_send_policy_ == FEC_ALARM_TRIGGER && !is_fec_timeout)) {
      ResetFecGroup();
      delegate_->OnResetFecGroup();
    } else {
      // TODO(zhongyi): Change the default 64 alignas value (used the default
      // value from CACHELINE_SIZE).
      ALIGNAS(64) char seralized_fec_buffer[kMaxPacketSize];
      SerializeFec(seralized_fec_buffer, kMaxPacketSize);
      OnSerializedPacket();
    }
  }

  if (!should_fec_protect_next_packet_ && fec_protect_ && !IsFecGroupOpen()) {
    StopFecProtectingPackets();
  }
}

QuicTime::Delta QuicPacketCreator::GetFecTimeout(
    QuicPacketNumber packet_number) {
  // Do not set up FEC alarm for |packet_number| it is not the first packet in
  // the current group.
  if (fec_group_.get() != nullptr &&
      (packet_number == fec_group_->FecGroupNumber())) {
    return QuicTime::Delta::Max(
        fec_timeout_, QuicTime::Delta::FromMilliseconds(kMinFecTimeoutMs));
  }
  return QuicTime::Delta::Infinite();
}

void QuicPacketCreator::OnCongestionWindowChange(
    QuicPacketCount max_packets_in_flight) {
  set_max_packets_per_fec_group(static_cast<size_t>(
      kMaxPacketsInFlightMultiplierForFecGroupSize * max_packets_in_flight));
}

void QuicPacketCreator::OnRttChange(QuicTime::Delta rtt) {
  fec_timeout_ = rtt.Multiply(rtt_multiplier_for_fec_timeout_);
}

void QuicPacketCreator::SetCurrentPath(
    QuicPathId path_id,
    QuicPacketNumber least_packet_awaited_by_peer,
    QuicPacketCount max_packets_in_flight) {
  if (packet_.path_id == path_id) {
    return;
  }

  if (HasPendingFrames()) {
    QUIC_BUG << "Unable to change paths when a packet is under construction.";
    return;
  }

  // Send FEC packet and close FEC group.
  MaybeSendFecPacketAndCloseGroup(/*force_send_fec=*/true,
                                  /*is_fec_timeout=*/false);
  // Save current packet number and load switching path's packet number.
  multipath_packet_number_[packet_.path_id] = packet_.packet_number;
  std::unordered_map<QuicPathId, QuicPacketNumber>::iterator it =
      multipath_packet_number_.find(path_id);
  // If path_id is not in the map, it's a new path. Set packet_number to 0.
  packet_.packet_number = it == multipath_packet_number_.end() ? 0 : it->second;
  packet_.path_id = path_id;
  DCHECK(packet_.path_id != kInvalidPathId);
  // Send path in packet if current path is not the default path.
  send_path_id_in_packet_ = packet_.path_id != kDefaultPathId ? true : false;
  // Switching path needs to update packet number length.
  UpdatePacketNumberLength(least_packet_awaited_by_peer, max_packets_in_flight);
}

}  // namespace net
