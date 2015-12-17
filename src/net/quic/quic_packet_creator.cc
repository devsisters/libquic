// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_packet_creator.h"

#include <algorithm>

#include "base/basictypes.h"
#include "base/logging.h"
#include "net/quic/crypto/quic_random.h"
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
const int64 kMinFecTimeoutMs = 5u;

}  // namespace

// A QuicRandom wrapper that gets a bucket of entropy and distributes it
// bit-by-bit. Replenishes the bucket as needed. Not thread-safe. Expose this
// class if single bit randomness is needed elsewhere.
class QuicRandomBoolSource {
 public:
  // random: Source of entropy. Not owned.
  explicit QuicRandomBoolSource(QuicRandom* random)
      : random_(random),
        bit_bucket_(0),
        bit_mask_(0) {}

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
  uint64 bit_bucket_;
  // The next available bit has "1" in the mask. Zero means empty bucket.
  uint64 bit_mask_;

  DISALLOW_COPY_AND_ASSIGN(QuicRandomBoolSource);
};

QuicPacketCreator::QuicPacketCreator(QuicConnectionId connection_id,
                                     QuicFramer* framer,
                                     QuicRandom* random_generator,
                                     DelegateInterface* delegate)
    : delegate_(delegate),
      debug_delegate_(nullptr),
      connection_id_(connection_id),
      encryption_level_(ENCRYPTION_NONE),
      has_ack_(false),
      has_stop_waiting_(false),
      framer_(framer),
      random_bool_source_(new QuicRandomBoolSource(random_generator)),
      current_path_(kDefaultPathId),
      packet_number_(0),
      should_fec_protect_next_packet_(false),
      fec_protect_(false),
      send_version_in_packet_(framer->perspective() == Perspective::IS_CLIENT),
      max_packet_length_(0),
      max_packets_per_fec_group_(kDefaultMaxPacketsPerFecGroup),
      connection_id_length_(PACKET_8BYTE_CONNECTION_ID),
      next_packet_number_length_(PACKET_1BYTE_PACKET_NUMBER),
      packet_number_length_(next_packet_number_length_),
      packet_size_(0),
      needs_padding_(false),
      fec_send_policy_(FEC_ANY_TRIGGER),
      fec_timeout_(QuicTime::Delta::Zero()),
      rtt_multiplier_for_fec_timeout_(kRttMultiplierForFecTimeout) {
  SetMaxPacketLength(kDefaultMaxPacketSize);
}

QuicPacketCreator::~QuicPacketCreator() {
}

void QuicPacketCreator::OnBuiltFecProtectedPayload(
    const QuicPacketHeader& header, StringPiece payload) {
  if (fec_group_.get() != nullptr) {
    DCHECK_NE(0u, header.fec_group);
    fec_group_->Update(encryption_level_, header, payload);
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
  max_packets_per_fec_group_ = max(kLowestMaxPacketsPerFecGroup,
                                   max_packets_per_fec_group);
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
    LOG_IF(DFATAL, packet_size_ != 0)
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
    LOG(DFATAL) << "Cannot start FEC protection when FEC is not enabled.";
    return;
  }
  // TODO(jri): This currently requires that the generator flush out any
  // pending frames when FEC protection is turned on. If current packet can be
  // converted to an FEC protected packet, do it. This will require the
  // generator to check if the resulting expansion still allows the incoming
  // frame to be added to the packet.
  if (HasPendingFrames()) {
    LOG(DFATAL) << "Cannot start FEC protection with pending frames.";
    return;
  }
  DCHECK(!fec_protect_);
  fec_protect_ = true;
}

void QuicPacketCreator::StopFecProtectingPackets() {
  if (fec_group_.get() != nullptr) {
    LOG(DFATAL) << "Cannot stop FEC protection with open FEC group.";
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
  packet_number_length_ = next_packet_number_length_;

  if (!fec_protect_) {
    return NOT_IN_FEC_GROUP;
  }
  // Start a new FEC group since protection is on. Set the fec group number to
  // the packet number of the next packet.
  fec_group_.reset(new QuicFecGroup(packet_number_ + 1));
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
  DCHECK_LE(least_packet_awaited_by_peer, packet_number_ + 1);
  // Since the packet creator will not change packet number length mid FEC
  // group, include the size of an FEC group to be safe.
  const QuicPacketNumber current_delta = max_packets_per_fec_group_ +
                                         packet_number_ + 1 -
                                         least_packet_awaited_by_peer;
  const uint64 delta = max(current_delta, max_packets_in_flight);
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
    Flush();
    return false;
  }
  if (fec_protection == MUST_FEC_PROTECT) {
    should_fec_protect_next_packet_ = true;
    MaybeStartFecProtection();
  }
  CreateStreamFrame(id, iov, iov_offset, offset, fin, frame);
  bool success = AddFrame(*frame,
                          /*save_retransmittable_frames=*/true, needs_padding);
  DCHECK(success);
  return true;
}

bool QuicPacketCreator::HasRoomForStreamFrame(QuicStreamId id,
                                              QuicStreamOffset offset) const {
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
    QuicPacketNumberLength packet_number_length,
    QuicStreamOffset offset,
    InFecGroup is_in_fec_group) {
  return GetPacketHeaderSize(connection_id_length, include_version,
                             /*include_path_id=*/false, packet_number_length,
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
            StreamFramePacketOverhead(connection_id_length_, kIncludeVersion,
                                      PACKET_6BYTE_PACKET_NUMBER, offset,
                                      IN_FEC_GROUP));

  InFecGroup is_in_fec_group = MaybeUpdateLengthsAndStartFec();

  LOG_IF(DFATAL, !HasRoomForStreamFrame(id, offset))
      << "No room for Stream frame, BytesFree: " << BytesFree()
      << " MinStreamFrameSize: "
      << QuicFramer::GetMinStreamFrameSize(id, offset, true, is_in_fec_group);

  if (iov_offset == iov.total_length) {
    LOG_IF(DFATAL, !fin)
        << "Creating a stream frame with no data or fin.";
    // Create a new packet for the fin, if necessary.
    *frame = QuicFrame(new QuicStreamFrame(id, true, offset, StringPiece()));
    return 0;
  }

  const size_t data_size = iov.total_length - iov_offset;
  size_t min_frame_size = QuicFramer::GetMinStreamFrameSize(
      id, offset, /* last_frame_in_packet= */ true, is_in_fec_group);
  size_t bytes_consumed = min<size_t>(BytesFree() - min_frame_size, data_size);

  bool set_fin = fin && bytes_consumed == data_size;  // Last frame.
  UniqueStreamBuffer buffer = NewStreamBuffer(bytes_consumed);
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
  if (FLAGS_quic_packet_creator_prefetch) {
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
      // Prefetch 2 cachelines worth of data to get the prefetcher started;
      // leave it to the hardware prefetcher after that.
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
  } else {
    while (iovnum < iov.iov_count && length > 0) {
      const size_t copy_len = min(length, iov.iov[iovnum].iov_len - iov_offset);
      memcpy(buffer, static_cast<char*>(iov.iov[iovnum].iov_base) + iov_offset,
             copy_len);
      iov_offset = 0;
      length -= copy_len;
      buffer += copy_len;
      ++iovnum;
    }
  }
  LOG_IF(DFATAL, length > 0) << "Failed to copy entire length to buffer.";
}

SerializedPacket QuicPacketCreator::ReserializeAllFrames(
    const RetransmittableFrames& frames,
    EncryptionLevel original_encryption_level,
    QuicPacketNumberLength original_length,
    char* buffer,
    size_t buffer_len) {
  DCHECK(fec_group_.get() == nullptr);
  const QuicPacketNumberLength saved_length = packet_number_length_;
  const QuicPacketNumberLength saved_next_length = next_packet_number_length_;
  const bool saved_should_fec_protect = fec_protect_;
  const bool needs_padding = needs_padding_;
  const EncryptionLevel default_encryption_level = encryption_level_;

  // Temporarily set the packet number length, stop FEC protection,
  // and change the encryption level.
  packet_number_length_ = original_length;
  next_packet_number_length_ = original_length;
  fec_protect_ = false;
  needs_padding_ = frames.needs_padding();
  // Only preserve the original encryption level if it's a handshake packet or
  // if we haven't gone forward secure.
  if (frames.HasCryptoHandshake() ||
      encryption_level_ != ENCRYPTION_FORWARD_SECURE) {
    encryption_level_ = original_encryption_level;
  }

  // Serialize the packet and restore the FEC and packet number length state.
  SerializedPacket serialized_packet =
      SerializeAllFrames(frames.frames(), buffer, buffer_len);
  packet_number_length_ = saved_length;
  next_packet_number_length_ = saved_next_length;
  fec_protect_ = saved_should_fec_protect;
  needs_padding_ = needs_padding;
  encryption_level_ = default_encryption_level;

  return serialized_packet;
}

SerializedPacket QuicPacketCreator::SerializeAllFrames(const QuicFrames& frames,
                                                       char* buffer,
                                                       size_t buffer_len) {
  LOG_IF(DFATAL, !queued_frames_.empty()) << "Frames already queued.";
  LOG_IF(DFATAL, frames.empty())
      << "Attempt to serialize empty packet";
  for (const QuicFrame& frame : frames) {
    bool success = AddFrame(frame, false, false);
    DCHECK(success);
  }
  SerializedPacket packet = SerializePacket(buffer, buffer_len);
  DCHECK(packet.retransmittable_frames == nullptr);
  return packet;
}

void QuicPacketCreator::Flush() {
  if (!HasPendingFrames()) {
    return;
  }

  // TODO(rtenneti): Change the default 64 alignas value (used the default
  // value from CACHELINE_SIZE).
  ALIGNAS(64) char seralized_packet_buffer[kMaxPacketSize];
  SerializedPacket serialized_packet =
      SerializePacket(seralized_packet_buffer, kMaxPacketSize);
  delegate_->OnSerializedPacket(&serialized_packet);
}

bool QuicPacketCreator::HasPendingFrames() const {
  return !queued_frames_.empty();
}

bool QuicPacketCreator::HasPendingRetransmittableFrames() const {
  return queued_retransmittable_frames_.get() != nullptr &&
         !queued_retransmittable_frames_->frames().empty();
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

size_t QuicPacketCreator::BytesFree() const {
  DCHECK_GE(max_plaintext_size_, PacketSize());
  return max_plaintext_size_ - min(max_plaintext_size_, PacketSize()
                                   + ExpansionOnNewFrame());
}

size_t QuicPacketCreator::PacketSize() const {
  if (!queued_frames_.empty()) {
    return packet_size_;
  }
  if (fec_group_.get() == nullptr) {
    // Update packet number length on packet and FEC boundary.
    packet_number_length_ = next_packet_number_length_;
  }
  packet_size_ = GetPacketHeaderSize(
      connection_id_length_, send_version_in_packet_, /*include_path_id=*/false,
      packet_number_length_, fec_protect_ ? IN_FEC_GROUP : NOT_IN_FEC_GROUP);
  return packet_size_;
}

bool QuicPacketCreator::AddSavedFrame(const QuicFrame& frame) {
  return AddFrame(frame,
                  /*save_retransmittable_frames=*/true,
                  /*needs_padding=*/false);
}

bool QuicPacketCreator::AddPaddedSavedFrame(const QuicFrame& frame) {
  return AddFrame(frame,
                  /*save_retransmittable_frames=*/true,
                  /*needs_padding=*/true);
}

SerializedPacket QuicPacketCreator::SerializePacket(
    char* encrypted_buffer,
    size_t encrypted_buffer_len) {
  DCHECK_LT(0u, encrypted_buffer_len);
  LOG_IF(DFATAL, queued_frames_.empty())
      << "Attempt to serialize empty packet";
  if (fec_group_.get() != nullptr) {
    DCHECK_GE(packet_number_ + 1, fec_group_->FecGroupNumber());
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
  size_t encrypted_length = 0u;
  if (FLAGS_quic_inplace_encryption) {
    size_t length = framer_->BuildDataPacket(header, queued_frames_,
                                             encrypted_buffer, packet_size_);
    if (length == 0) {
      LOG(DFATAL) << "Failed to serialize " << queued_frames_.size()
                  << " frames.";
      return NoPacket();
    }

    // TODO(ianswett) Consider replacing QuicPacket with something else, since
    // it's only used to provide convenience methods to FEC and encryption.
    QuicPacket packet(encrypted_buffer, length,
                      /* owns_buffer */ false,
                      header.public_header.connection_id_length,
                      header.public_header.version_flag,
                      header.public_header.packet_number_length);
    OnBuiltFecProtectedPayload(header, packet.FecProtectedData());

    // Because of possible truncation, we can't be confident that our
    // packet size calculation worked correctly.
    if (!possibly_truncated_by_length) {
      DCHECK_EQ(packet_size_, length);
    }
    // Immediately encrypt the packet, to ensure we don't encrypt the same
    // packet number multiple times.
    encrypted_length =
        framer_->EncryptPayload(encryption_level_, packet_number_, packet,
                                encrypted_buffer, encrypted_buffer_len);
  } else {
    // The optimized encryption algorithm implementations run faster when
    // operating on aligned memory.
    // TODO(rtenneti): Change the default 64 alignas value (used the default
    // value from CACHELINE_SIZE).
    ALIGNAS(64) char buffer[kMaxPacketSize];
    size_t length =
        framer_->BuildDataPacket(header, queued_frames_, buffer, packet_size_);
    if (length == 0) {
      LOG(DFATAL) << "Failed to serialize " << queued_frames_.size()
                  << " frames.";
      return NoPacket();
    }

    // TODO(ianswett) Consider replacing QuicPacket with something else, since
    // it's only used to provide convenience methods to FEC and encryption.
    QuicPacket packet(buffer, length,
                      /* owns_buffer */ false,
                      header.public_header.connection_id_length,
                      header.public_header.version_flag,
                      header.public_header.packet_number_length);
    OnBuiltFecProtectedPayload(header, packet.FecProtectedData());

    // Because of possible truncation, we can't be confident that our
    // packet size calculation worked correctly.
    if (!possibly_truncated_by_length) {
      DCHECK_EQ(packet_size_, length);
    }
    // Immediately encrypt the packet, to ensure we don't encrypt the same
    // packet number multiple times.
    encrypted_length =
        framer_->EncryptPayload(encryption_level_, packet_number_, packet,
                                encrypted_buffer, encrypted_buffer_len);
  }
  if (encrypted_length == 0) {
    LOG(DFATAL) << "Failed to encrypt packet number " << packet_number_;
    return NoPacket();
  }

  // Update |needs_padding_| flag of |queued_retransmittable_frames_| here, and
  // not in AddFrame, because when the first padded frame is added to the queue,
  // it might not be retransmittable, and hence the flag would end up being not
  // set.
  if (queued_retransmittable_frames_.get() != nullptr) {
    queued_retransmittable_frames_->set_needs_padding(needs_padding_);
  }

  const bool has_ack = has_ack_;
  const bool has_stop_waiting = has_stop_waiting_;
  has_ack_ = false;
  has_stop_waiting_ = false;
  packet_size_ = 0;
  queued_frames_.clear();
  needs_padding_ = false;
  return SerializedPacket(
      header.packet_number, header.public_header.packet_number_length,
      encrypted_buffer, encrypted_length, /* owns_buffer*/ false,
      QuicFramer::GetPacketEntropyHash(header),
      queued_retransmittable_frames_.release(), has_ack, has_stop_waiting,
      encryption_level_);
}

SerializedPacket QuicPacketCreator::SerializeFec(char* buffer,
                                                 size_t buffer_len) {
  DCHECK_LT(0u, buffer_len);
  if (fec_group_.get() == nullptr || fec_group_->NumReceivedPackets() <= 0) {
    LOG(DFATAL) << "SerializeFEC called but no group or zero packets in group.";
    // TODO(jri): Make this a public method of framer?
    return NoPacket();
  }
  DCHECK_EQ(0u, queued_frames_.size());
  QuicPacketHeader header;
  FillPacketHeader(fec_group_->FecGroupNumber(), true, &header);
  scoped_ptr<QuicPacket> packet(
      framer_->BuildFecPacket(header, fec_group_->PayloadParity()));
  fec_group_.reset(nullptr);
  packet_size_ = 0;
  LOG_IF(DFATAL, packet == nullptr)
      << "Failed to serialize fec packet for group:"
      << fec_group_->FecGroupNumber();
  DCHECK_GE(max_packet_length_, packet->length());
  // Immediately encrypt the packet, to ensure we don't encrypt the same packet
  // packet number multiple times.
  size_t encrypted_length = framer_->EncryptPayload(
      encryption_level_, packet_number_, *packet, buffer, buffer_len);
  if (encrypted_length == 0) {
    LOG(DFATAL) << "Failed to encrypt packet number " << packet_number_;
    return NoPacket();
  }
  SerializedPacket serialized(header.packet_number,
                              header.public_header.packet_number_length, buffer,
                              encrypted_length, /* owns_buffer */ false,
                              QuicFramer::GetPacketEntropyHash(header), nullptr,
                              false, false, encryption_level_);
  serialized.is_fec_packet = true;
  return serialized;
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

SerializedPacket QuicPacketCreator::NoPacket() {
  return SerializedPacket(0, PACKET_1BYTE_PACKET_NUMBER, nullptr, 0, nullptr,
                          false, false);
}

void QuicPacketCreator::FillPacketHeader(QuicFecGroupNumber fec_group,
                                         bool fec_flag,
                                         QuicPacketHeader* header) {
  header->public_header.connection_id = connection_id_;
  header->public_header.connection_id_length = connection_id_length_;
  header->public_header.reset_flag = false;
  header->public_header.version_flag = send_version_in_packet_;
  header->fec_flag = fec_flag;
  header->packet_number = ++packet_number_;
  header->public_header.packet_number_length = packet_number_length_;
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
                                 bool save_retransmittable_frames,
                                 bool needs_padding) {
  DVLOG(1) << "Adding frame: " << frame;
  InFecGroup is_in_fec_group = MaybeUpdateLengthsAndStartFec();

  size_t frame_len = framer_->GetSerializedFrameLength(
      frame, BytesFree(), queued_frames_.empty(), true, is_in_fec_group,
      packet_number_length_);
  if (frame_len == 0) {
    // Current open packet is full.
    Flush();
    return false;
  }
  DCHECK_LT(0u, packet_size_);
  packet_size_ += ExpansionOnNewFrame() + frame_len;

  if (save_retransmittable_frames && ShouldRetransmit(frame)) {
    if (queued_retransmittable_frames_.get() == nullptr) {
      queued_retransmittable_frames_.reset(new RetransmittableFrames());
    }
    queued_frames_.push_back(queued_retransmittable_frames_->AddFrame(frame));
  } else {
    queued_frames_.push_back(frame);
  }

  if (frame.type == ACK_FRAME) {
    has_ack_ = true;
  }
  if (frame.type == STOP_WAITING_FRAME) {
    has_stop_waiting_ = true;
  }
  if (needs_padding) {
    needs_padding_ = true;
  }
  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnFrameAddedToPacket(frame);
  }

  return true;
}

void QuicPacketCreator::MaybeAddPadding() {
  if (!needs_padding_) {
    return;
  }

  if (BytesFree() == 0) {
    // Don't pad full packets.
    return;
  }

  bool success = AddFrame(QuicFrame(QuicPaddingFrame()), false, false);
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
    if (fec_send_policy_ == FEC_ALARM_TRIGGER && !is_fec_timeout) {
      ResetFecGroup();
      delegate_->OnResetFecGroup();
    } else {
      // TODO(zhongyi): Change the default 64 alignas value (used the default
      // value from CACHELINE_SIZE).
      ALIGNAS(64) char seralized_fec_buffer[kMaxPacketSize];
      SerializedPacket serialized_fec =
          SerializeFec(seralized_fec_buffer, kMaxPacketSize);
      delegate_->OnSerializedPacket(&serialized_fec);
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
  if (current_path_ == path_id) {
    return;
  }

  if (HasPendingFrames()) {
    LOG(DFATAL)
        << "Unable to change paths when a packet is under construction.";
    return;
  }

  // Send FEC packet and close FEC group.
  MaybeSendFecPacketAndCloseGroup(/*force_send_fec=*/true,
                                  /*is_fec_timeout=*/false);
  // Save current packet number and load switching path's packet number.
  multipath_packet_number_[current_path_] = packet_number_;
  hash_map<QuicPathId, QuicPacketNumber>::iterator it =
      multipath_packet_number_.find(path_id);
  // If path_id is not in the map, it's a new path. Set packet_number to 0.
  packet_number_ = it == multipath_packet_number_.end() ? 0 : it->second;
  current_path_ = path_id;
  // Switching path needs to update packet number length.
  UpdatePacketNumberLength(least_packet_awaited_by_peer, max_packets_in_flight);
}

}  // namespace net
