// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_packet_generator.h"

#include "base/basictypes.h"
#include "base/logging.h"
#include "net/quic/quic_fec_group.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;

namespace net {

namespace {

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

class QuicAckNotifier;

QuicPacketGenerator::QuicPacketGenerator(QuicConnectionId connection_id,
                                         QuicFramer* framer,
                                         QuicRandom* random_generator,
                                         DelegateInterface* delegate)
    : delegate_(delegate),
      debug_delegate_(nullptr),
      packet_creator_(connection_id, framer, random_generator),
      batch_mode_(false),
      fec_timeout_(QuicTime::Delta::Zero()),
      rtt_multiplier_for_fec_timeout_(kRttMultiplierForFecTimeout),
      should_fec_protect_(false),
      fec_send_policy_(FEC_ANY_TRIGGER),
      should_send_ack_(false),
      should_send_stop_waiting_(false),
      ack_queued_(false),
      stop_waiting_queued_(false),
      max_packet_length_(kDefaultMaxPacketSize) {}

QuicPacketGenerator::~QuicPacketGenerator() {
  for (QuicFrame& frame : queued_control_frames_) {
    switch (frame.type) {
      case PADDING_FRAME:
      case MTU_DISCOVERY_FRAME:
      case PING_FRAME:
        break;
      case STREAM_FRAME:
        delete frame.stream_frame;
        break;
      case ACK_FRAME:
        delete frame.ack_frame;
        break;
      case RST_STREAM_FRAME:
        delete frame.rst_stream_frame;
        break;
      case CONNECTION_CLOSE_FRAME:
        delete frame.connection_close_frame;
        break;
      case GOAWAY_FRAME:
        delete frame.goaway_frame;
        break;
      case WINDOW_UPDATE_FRAME:
        delete frame.window_update_frame;
        break;
      case BLOCKED_FRAME:
        delete frame.blocked_frame;
        break;
      case STOP_WAITING_FRAME:
        delete frame.stop_waiting_frame;
        break;
      case NUM_FRAME_TYPES:
        DCHECK(false) << "Cannot delete type: " << frame.type;
    }
  }
}

void QuicPacketGenerator::OnCongestionWindowChange(
    QuicPacketCount max_packets_in_flight) {
  packet_creator_.set_max_packets_per_fec_group(
      static_cast<size_t>(kMaxPacketsInFlightMultiplierForFecGroupSize *
                          max_packets_in_flight));
}

void QuicPacketGenerator::OnRttChange(QuicTime::Delta rtt) {
  fec_timeout_ = rtt.Multiply(rtt_multiplier_for_fec_timeout_);
}

void QuicPacketGenerator::SetShouldSendAck(bool also_send_stop_waiting) {
  if (ack_queued_) {
    // Ack already queued, nothing to do.
    return;
  }

  if (also_send_stop_waiting && stop_waiting_queued_) {
    LOG(DFATAL) << "Should only ever be one pending stop waiting frame.";
    return;
  }

  should_send_ack_ = true;
  should_send_stop_waiting_ = also_send_stop_waiting;
  SendQueuedFrames(/*flush=*/false, /*is_fec_timeout=*/false);
}

void QuicPacketGenerator::AddControlFrame(const QuicFrame& frame) {
  queued_control_frames_.push_back(frame);
  SendQueuedFrames(/*flush=*/false, /*is_fec_timeout=*/false);
}

QuicConsumedData QuicPacketGenerator::ConsumeData(
    QuicStreamId id,
    QuicIOVector iov,
    QuicStreamOffset offset,
    bool fin,
    FecProtection fec_protection,
    QuicAckListenerInterface* listener) {
  bool has_handshake = id == kCryptoStreamId;
  // To make reasoning about crypto frames easier, we don't combine them with
  // other retransmittable frames in a single packet.
  const bool flush =
      has_handshake && packet_creator_.HasPendingRetransmittableFrames();
  SendQueuedFrames(flush, /*is_fec_timeout=*/false);

  size_t total_bytes_consumed = 0;
  bool fin_consumed = false;

  if (!packet_creator_.HasRoomForStreamFrame(id, offset)) {
    SerializeAndSendPacket();
  }

  if (fec_protection == MUST_FEC_PROTECT) {
    MaybeStartFecProtection();
  }

  if (!fin && (iov.total_length == 0)) {
    LOG(DFATAL) << "Attempt to consume empty data without FIN.";
    return QuicConsumedData(0, false);
  }

  int frames_created = 0;
  while (delegate_->ShouldGeneratePacket(
      HAS_RETRANSMITTABLE_DATA, has_handshake ? IS_HANDSHAKE : NOT_HANDSHAKE)) {
    QuicFrame frame;
    UniqueStreamBuffer buffer;
    size_t bytes_consumed = packet_creator_.CreateStreamFrame(
        id, iov, total_bytes_consumed, offset + total_bytes_consumed, fin,
        &frame, &buffer);
    ++frames_created;

    if (!AddFrame(frame, buffer.Pass(), has_handshake)) {
      LOG(DFATAL) << "Failed to add stream frame.";
      // Inability to add a STREAM frame creates an unrecoverable hole in a
      // the stream, so it's best to close the connection.
      delegate_->CloseConnection(QUIC_INTERNAL_ERROR, false);
      return QuicConsumedData(0, false);
    }
    if (listener != nullptr) {
      ack_listeners_.push_back(AckListenerWrapper(listener, bytes_consumed));
    }

    total_bytes_consumed += bytes_consumed;
    fin_consumed = fin && total_bytes_consumed == iov.total_length;
    DCHECK(total_bytes_consumed == iov.total_length ||
           packet_creator_.BytesFree() == 0u);

    if (!InBatchMode() || !packet_creator_.HasRoomForStreamFrame(id, offset)) {
      // TODO(rtenneti): remove MaybeSendFecPacketAndCloseGroup() from inside
      // SerializeAndSendPacket() and make it an explicit call here (and
      // elsewhere where we call SerializeAndSendPacket?).
      SerializeAndSendPacket();
    }

    if (total_bytes_consumed == iov.total_length) {
      // We're done writing the data. Exit the loop.
      // We don't make this a precondition because we could have 0 bytes of data
      // if we're simply writing a fin.
      if (fec_protection == MUST_FEC_PROTECT) {
        // Turn off FEC protection when we're done writing protected data.
        DVLOG(1) << "Turning FEC protection OFF";
        should_fec_protect_ = false;
      }
      break;
    }
  }

  // Don't allow the handshake to be bundled with other retransmittable frames.
  if (has_handshake) {
    SendQueuedFrames(/*flush=*/true, /*is_fec_timeout=*/false);
  }

  // Try to close FEC group since we've either run out of data to send or we're
  // blocked.
  MaybeSendFecPacketAndCloseGroup(/*force=*/false, /*is_fec_timeout=*/false);

  DCHECK(InBatchMode() || !packet_creator_.HasPendingFrames());
  return QuicConsumedData(total_bytes_consumed, fin_consumed);
}

void QuicPacketGenerator::GenerateMtuDiscoveryPacket(
    QuicByteCount target_mtu,
    QuicAckListenerInterface* listener) {
  // MTU discovery frames must be sent by themselves.
  DCHECK(!InBatchMode() && !packet_creator_.HasPendingFrames());
  const QuicByteCount current_mtu = GetMaxPacketLength();

  // The MTU discovery frame is allocated on the stack, since it is going to be
  // serialized within this function.
  QuicMtuDiscoveryFrame mtu_discovery_frame;
  QuicFrame frame(mtu_discovery_frame);

  // Send the probe packet with the new length.
  SetMaxPacketLength(target_mtu, /*force=*/true);
  const bool success = AddFrame(frame, nullptr, /*needs_padding=*/true);
  if (listener != nullptr) {
    ack_listeners_.push_back(AckListenerWrapper(listener, 0));
  }
  SerializeAndSendPacket();
  // The only reason AddFrame can fail is that the packet is too full to fit in
  // a ping.  This is not possible for any sane MTU.
  DCHECK(success);

  // Reset the packet length back.
  SetMaxPacketLength(current_mtu, /*force=*/true);
}

bool QuicPacketGenerator::CanSendWithNextPendingFrameAddition() const {
  DCHECK(HasPendingFrames());
  HasRetransmittableData retransmittable =
      (should_send_ack_ || should_send_stop_waiting_)
          ? NO_RETRANSMITTABLE_DATA
          : HAS_RETRANSMITTABLE_DATA;
  if (retransmittable == HAS_RETRANSMITTABLE_DATA) {
      DCHECK(!queued_control_frames_.empty());  // These are retransmittable.
  }
  return delegate_->ShouldGeneratePacket(retransmittable, NOT_HANDSHAKE);
}

void QuicPacketGenerator::SendQueuedFrames(bool flush, bool is_fec_timeout) {
  // Only add pending frames if we are SURE we can then send the whole packet.
  while (HasPendingFrames() &&
         (flush || CanSendWithNextPendingFrameAddition())) {
    if (!AddNextPendingFrame()) {
      // Packet was full, so serialize and send it.
      SerializeAndSendPacket();
    }
  }
  if (packet_creator_.HasPendingFrames() && (flush || !InBatchMode())) {
    SerializeAndSendPacket();
  }
  MaybeSendFecPacketAndCloseGroup(flush, is_fec_timeout);
}

void QuicPacketGenerator::MaybeStartFecProtection() {
  if (!packet_creator_.IsFecEnabled()) {
    return;
  }
  DVLOG(1) << "Turning FEC protection ON";
  should_fec_protect_ = true;
  if (packet_creator_.IsFecProtected()) {
    // Only start creator's FEC protection if not already on.
    return;
  }
  if (HasQueuedFrames()) {
    // TODO(jri): This currently requires that the generator flush out any
    // pending frames when FEC protection is turned on. If current packet can be
    // converted to an FEC protected packet, do it. This will require the
    // generator to check if the resulting expansion still allows the incoming
    // frame to be added to the packet.
    SendQueuedFrames(/*flush=*/true, /*is_fec_timeout=*/false);
  }
  packet_creator_.StartFecProtectingPackets();
  DCHECK(packet_creator_.IsFecProtected());
}

void QuicPacketGenerator::MaybeSendFecPacketAndCloseGroup(bool force,
                                                          bool is_fec_timeout) {
  if (ShouldSendFecPacket(force)) {
    // If we want to send FEC packet only when FEC alaram goes off and if it is
    // not a FEC timeout then close the group and dont send FEC packet.
    if (fec_send_policy_ == FEC_ALARM_TRIGGER && !is_fec_timeout) {
      ResetFecGroup();
    } else {
      // TODO(jri): SerializeFec can return a NULL packet, and this should cause
      // an early return, with a call to delegate_->OnPacketGenerationError.
      char buffer[kMaxPacketSize];
      SerializedPacket serialized_fec =
          packet_creator_.SerializeFec(buffer, kMaxPacketSize);
      DCHECK(serialized_fec.packet);
      delegate_->OnSerializedPacket(serialized_fec);
    }
  }

  // Turn FEC protection off if creator's protection is on and the creator
  // does not have an open FEC group.
  // Note: We only wait until the frames queued in the creator are flushed;
  // pending frames in the generator will not keep us from turning FEC off.
  if (!should_fec_protect_ && packet_creator_.IsFecProtected() &&
      !packet_creator_.IsFecGroupOpen()) {
    packet_creator_.StopFecProtectingPackets();
    DCHECK(!packet_creator_.IsFecProtected());
  }
}

bool QuicPacketGenerator::ShouldSendFecPacket(bool force) {
  return packet_creator_.IsFecProtected() &&
         !packet_creator_.HasPendingFrames() &&
         packet_creator_.ShouldSendFec(force);
}

void QuicPacketGenerator::ResetFecGroup() {
  DCHECK(packet_creator_.IsFecGroupOpen());
  packet_creator_.ResetFecGroup();
  delegate_->OnResetFecGroup();
}

void QuicPacketGenerator::OnFecTimeout() {
  DCHECK(!InBatchMode());
  if (!ShouldSendFecPacket(true)) {
    LOG(DFATAL) << "No FEC packet to send on FEC timeout.";
    return;
  }
  // Flush out any pending frames in the generator and the creator, and then
  // send out FEC packet.
  SendQueuedFrames(/*flush=*/true, /*is_fec_timeout=*/true);
  MaybeSendFecPacketAndCloseGroup(/*force=*/true, /*is_fec_timeout=*/true);
}

QuicTime::Delta QuicPacketGenerator::GetFecTimeout(
    QuicPacketNumber packet_number) {
  // Do not set up FEC alarm for |packet_number| it is not the first packet in
  // the current group.
  if (packet_creator_.IsFecGroupOpen() &&
      (packet_number == packet_creator_.fec_group_number())) {
    return QuicTime::Delta::Max(
        fec_timeout_, QuicTime::Delta::FromMilliseconds(kMinFecTimeoutMs));
  }
  return QuicTime::Delta::Infinite();
}

bool QuicPacketGenerator::InBatchMode() {
  return batch_mode_;
}

void QuicPacketGenerator::StartBatchOperations() {
  batch_mode_ = true;
}

void QuicPacketGenerator::FinishBatchOperations() {
  batch_mode_ = false;
  SendQueuedFrames(/*flush=*/false, /*is_fec_timeout=*/false);
}

void QuicPacketGenerator::FlushAllQueuedFrames() {
  SendQueuedFrames(/*flush=*/true, /*is_fec_timeout=*/false);
}

bool QuicPacketGenerator::HasQueuedFrames() const {
  return packet_creator_.HasPendingFrames() || HasPendingFrames();
}

bool QuicPacketGenerator::HasPendingFrames() const {
  return should_send_ack_ || should_send_stop_waiting_ ||
         !queued_control_frames_.empty();
}

bool QuicPacketGenerator::AddNextPendingFrame() {
  if (should_send_ack_) {
    delegate_->PopulateAckFrame(&pending_ack_frame_);
    ack_queued_ = true;
    // If we can't this add the frame now, then we still need to do so later.
    should_send_ack_ = !AddFrame(QuicFrame(&pending_ack_frame_), nullptr,
                                 /*needs_padding=*/false);
    // Return success if we have cleared out this flag (i.e., added the frame).
    // If we still need to send, then the frame is full, and we have failed.
    return !should_send_ack_;
  }

  if (should_send_stop_waiting_) {
    delegate_->PopulateStopWaitingFrame(&pending_stop_waiting_frame_);
    stop_waiting_queued_ = true;
    // If we can't this add the frame now, then we still need to do so later.
    should_send_stop_waiting_ =
        !AddFrame(QuicFrame(&pending_stop_waiting_frame_), nullptr,
                  /*needs_padding=*/false);
    // Return success if we have cleared out this flag (i.e., added the frame).
    // If we still need to send, then the frame is full, and we have failed.
    return !should_send_stop_waiting_;
  }

  LOG_IF(DFATAL, queued_control_frames_.empty())
      << "AddNextPendingFrame called with no queued control frames.";
  if (!AddFrame(queued_control_frames_.back(), nullptr,
                /*needs_padding=*/false)) {
    // Packet was full.
    return false;
  }
  queued_control_frames_.pop_back();
  return true;
}

bool QuicPacketGenerator::AddFrame(const QuicFrame& frame,
                                   UniqueStreamBuffer buffer,
                                   bool needs_padding) {
  bool success = needs_padding
                     ? packet_creator_.AddPaddedSavedFrame(frame, buffer.Pass())
                     : packet_creator_.AddSavedFrame(frame, buffer.Pass());
  if (success && debug_delegate_) {
    debug_delegate_->OnFrameAddedToPacket(frame);
  }
  return success;
}

void QuicPacketGenerator::SerializeAndSendPacket() {
  // The optimized encryption algorithm implementations run faster when
  // operating on aligned memory.
  //
  // TODO(rtenneti): Change the default 64 alignas value (used the default
  // value from CACHELINE_SIZE).
  ALIGNAS(64) char buffer[kMaxPacketSize];
  SerializedPacket serialized_packet =
      packet_creator_.SerializePacket(buffer, kMaxPacketSize);
  if (serialized_packet.packet == nullptr) {
    LOG(DFATAL) << "Failed to SerializePacket. fec_policy:" << fec_send_policy_
                << " should_fec_protect_:" << should_fec_protect_;
    delegate_->CloseConnection(QUIC_FAILED_TO_SERIALIZE_PACKET, false);
    return;
  }

  // There may be AckListeners interested in this packet.
  serialized_packet.listeners.swap(ack_listeners_);
  ack_listeners_.clear();

  delegate_->OnSerializedPacket(serialized_packet);
  MaybeSendFecPacketAndCloseGroup(/*force=*/false, /*is_fec_timeout=*/false);

  // Maximum packet size may be only enacted while no packet is currently being
  // constructed, so here we have a good opportunity to actually change it.
  if (packet_creator_.CanSetMaxPacketLength()) {
    packet_creator_.SetMaxPacketLength(max_packet_length_);
  }

  // The packet has now been serialized, so the frames are no longer queued.
  ack_queued_ = false;
  stop_waiting_queued_ = false;
}

void QuicPacketGenerator::StopSendingVersion() {
  packet_creator_.StopSendingVersion();
}

QuicPacketNumber QuicPacketGenerator::packet_number() const {
  return packet_creator_.packet_number();
}

QuicByteCount QuicPacketGenerator::GetMaxPacketLength() const {
  return max_packet_length_;
}

QuicByteCount QuicPacketGenerator::GetCurrentMaxPacketLength() const {
  return packet_creator_.max_packet_length();
}

void QuicPacketGenerator::SetMaxPacketLength(QuicByteCount length, bool force) {
  // If we cannot immediately set new maximum packet length, and the |force|
  // flag is set, we have to flush the contents of the queue and close existing
  // FEC group.
  if (!packet_creator_.CanSetMaxPacketLength() && force) {
    SendQueuedFrames(/*flush=*/true, /*is_fec_timeout=*/false);
    MaybeSendFecPacketAndCloseGroup(/*force=*/true, /*is_fec_timeout=*/false);
    DCHECK(packet_creator_.CanSetMaxPacketLength());
  }

  max_packet_length_ = length;
  if (packet_creator_.CanSetMaxPacketLength()) {
    packet_creator_.SetMaxPacketLength(length);
  }
}

QuicEncryptedPacket* QuicPacketGenerator::SerializeVersionNegotiationPacket(
    const QuicVersionVector& supported_versions) {
  return packet_creator_.SerializeVersionNegotiationPacket(supported_versions);
}

SerializedPacket QuicPacketGenerator::ReserializeAllFrames(
    const RetransmittableFrames& frames,
    QuicPacketNumberLength original_length,
    char* buffer,
    size_t buffer_len) {
  return packet_creator_.ReserializeAllFrames(frames, original_length, buffer,
                                              buffer_len);
}

void QuicPacketGenerator::UpdateSequenceNumberLength(
    QuicPacketNumber least_packet_awaited_by_peer,
    QuicPacketCount max_packets_in_flight) {
  return packet_creator_.UpdatePacketNumberLength(least_packet_awaited_by_peer,
                                                  max_packets_in_flight);
}

void QuicPacketGenerator::SetConnectionIdLength(uint32 length) {
  if (length == 0) {
    packet_creator_.set_connection_id_length(PACKET_0BYTE_CONNECTION_ID);
  } else if (length == 1) {
    packet_creator_.set_connection_id_length(PACKET_1BYTE_CONNECTION_ID);
  } else if (length <= 4) {
    packet_creator_.set_connection_id_length(PACKET_4BYTE_CONNECTION_ID);
  } else {
    packet_creator_.set_connection_id_length(PACKET_8BYTE_CONNECTION_ID);
  }
}

void QuicPacketGenerator::set_encryption_level(EncryptionLevel level) {
  packet_creator_.set_encryption_level(level);
}

void QuicPacketGenerator::SetEncrypter(EncryptionLevel level,
                                       QuicEncrypter* encrypter) {
  packet_creator_.SetEncrypter(level, encrypter);
}

}  // namespace net
