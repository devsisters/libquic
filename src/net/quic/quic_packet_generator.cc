// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_packet_generator.h"

#include "base/logging.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_fec_group.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;

namespace net {

class QuicAckNotifier;

QuicPacketGenerator::QuicPacketGenerator(QuicConnectionId connection_id,
                                         QuicFramer* framer,
                                         QuicRandom* random_generator,
                                         QuicBufferAllocator* buffer_allocator,
                                         DelegateInterface* delegate)
    : delegate_(delegate),
      packet_creator_(connection_id,
                      framer,
                      random_generator,
                      buffer_allocator,
                      delegate),
      batch_mode_(false),
      should_send_ack_(false),
      should_send_stop_waiting_(false),
      max_packet_length_(kDefaultMaxPacketSize) {}

QuicPacketGenerator::~QuicPacketGenerator() {
  QuicUtils::DeleteFrames(&queued_control_frames_);
}

void QuicPacketGenerator::OnCongestionWindowChange(
    QuicPacketCount max_packets_in_flight) {
  packet_creator_.OnCongestionWindowChange(max_packets_in_flight);
}

void QuicPacketGenerator::OnRttChange(QuicTime::Delta rtt) {
  packet_creator_.OnRttChange(rtt);
}

void QuicPacketGenerator::SetShouldSendAck(bool also_send_stop_waiting) {
  if (packet_creator_.has_ack()) {
    // Ack already queued, nothing to do.
    return;
  }

  if (also_send_stop_waiting && packet_creator_.has_stop_waiting()) {
    QUIC_BUG << "Should only ever be one pending stop waiting frame.";
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
    packet_creator_.Flush();
  }

  if (!fin && (iov.total_length == 0)) {
    QUIC_BUG << "Attempt to consume empty data without FIN.";
    return QuicConsumedData(0, false);
  }

  while (delegate_->ShouldGeneratePacket(
      HAS_RETRANSMITTABLE_DATA, has_handshake ? IS_HANDSHAKE : NOT_HANDSHAKE)) {
    QuicFrame frame;
    if (!packet_creator_.ConsumeData(id, iov, total_bytes_consumed,
                                     offset + total_bytes_consumed, fin,
                                     has_handshake, &frame, fec_protection)) {
      // The creator is always flushed if there's not enough room for a new
      // stream frame before ConsumeData, so ConsumeData should always succeed.
      QUIC_BUG << "Failed to ConsumeData, stream:" << id;
      return QuicConsumedData(0, false);
    }

    // A stream frame is created and added.
    size_t bytes_consumed = frame.stream_frame->frame_length;
    if (listener != nullptr) {
      packet_creator_.AddAckListener(listener, bytes_consumed);
    }
    total_bytes_consumed += bytes_consumed;
    fin_consumed = fin && total_bytes_consumed == iov.total_length;
    DCHECK(total_bytes_consumed == iov.total_length ||
           (bytes_consumed > 0 && packet_creator_.HasPendingFrames()));

    if (!InBatchMode()) {
      // TODO(rtenneti): remove MaybeSendFecPacketAndCloseGroup() from inside
      // SerializeAndSendPacket() and make it an explicit call here (and
      // elsewhere where we call SerializeAndSendPacket?).
      packet_creator_.Flush();
    }

    if (total_bytes_consumed == iov.total_length) {
      // We're done writing the data. Exit the loop.
      // We don't make this a precondition because we could have 0 bytes of data
      // if we're simply writing a fin.
      break;
    }
    // TODO(ianswett): Move to having the creator flush itself when it's full.
    packet_creator_.Flush();
  }

  // Don't allow the handshake to be bundled with other retransmittable frames.
  if (has_handshake) {
    SendQueuedFrames(/*flush=*/true, /*is_fec_timeout=*/false);
  }

  // Try to close FEC group since we've either run out of data to send or we're
  // blocked.
  packet_creator_.MaybeSendFecPacketAndCloseGroup(/*force_send_fec=*/false,
                                                  /*is_fec_timeout=*/false);

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
  const bool success = packet_creator_.AddPaddedSavedFrame(frame);
  if (listener != nullptr) {
    packet_creator_.AddAckListener(listener, 0);
  }
  packet_creator_.Flush();
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
    AddNextPendingFrame();
  }
  if (flush || !InBatchMode()) {
    packet_creator_.Flush();
  }
  packet_creator_.MaybeSendFecPacketAndCloseGroup(flush, is_fec_timeout);
}

void QuicPacketGenerator::OnFecTimeout() {
  DCHECK(!InBatchMode());
  if (!packet_creator_.ShouldSendFec(true)) {
    QUIC_BUG << "No FEC packet to send on FEC timeout.";
    return;
  }
  // Flush out any pending frames in the generator and the creator, and then
  // send out FEC packet.
  SendQueuedFrames(/*flush=*/true, /*is_fec_timeout=*/true);
}

QuicTime::Delta QuicPacketGenerator::GetFecTimeout(
    QuicPacketNumber packet_number) {
  return packet_creator_.GetFecTimeout(packet_number);
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
    // If we can't this add the frame now, then we still need to do so later.
    should_send_ack_ =
        !packet_creator_.AddSavedFrame(QuicFrame(&pending_ack_frame_));
    // Return success if we have cleared out this flag (i.e., added the frame).
    // If we still need to send, then the frame is full, and we have failed.
    return !should_send_ack_;
  }

  if (should_send_stop_waiting_) {
    delegate_->PopulateStopWaitingFrame(&pending_stop_waiting_frame_);
    // If we can't this add the frame now, then we still need to do so later.
    should_send_stop_waiting_ =
        !packet_creator_.AddSavedFrame(QuicFrame(&pending_stop_waiting_frame_));
    // Return success if we have cleared out this flag (i.e., added the frame).
    // If we still need to send, then the frame is full, and we have failed.
    return !should_send_stop_waiting_;
  }

  QUIC_BUG_IF(queued_control_frames_.empty())
      << "AddNextPendingFrame called with no queued control frames.";
  if (!packet_creator_.AddSavedFrame(queued_control_frames_.back())) {
    // Packet was full.
    return false;
  }
  queued_control_frames_.pop_back();
  return true;
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
    packet_creator_.MaybeSendFecPacketAndCloseGroup(/*force_send_fec=*/true,
                                                    /*is_fec_timeout=*/false);
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

void QuicPacketGenerator::ReserializeAllFrames(
    const PendingRetransmission& retransmission,
    char* buffer,
    size_t buffer_len) {
  packet_creator_.ReserializeAllFrames(retransmission, buffer, buffer_len);
}

void QuicPacketGenerator::UpdateSequenceNumberLength(
    QuicPacketNumber least_packet_awaited_by_peer,
    QuicPacketCount max_packets_in_flight) {
  return packet_creator_.UpdatePacketNumberLength(least_packet_awaited_by_peer,
                                                  max_packets_in_flight);
}

void QuicPacketGenerator::SetConnectionIdLength(uint32_t length) {
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

void QuicPacketGenerator::SetCurrentPath(
    QuicPathId path_id,
    QuicPacketNumber least_packet_awaited_by_peer,
    QuicPacketCount max_packets_in_flight) {
  packet_creator_.SetCurrentPath(path_id, least_packet_awaited_by_peer,
                                 max_packets_in_flight);
}

void QuicPacketGenerator::set_rtt_multiplier_for_fec_timeout(
    float rtt_multiplier_for_fec_timeout) {
  packet_creator_.set_rtt_multiplier_for_fec_timeout(
      rtt_multiplier_for_fec_timeout);
}

FecSendPolicy QuicPacketGenerator::fec_send_policy() {
  return packet_creator_.fec_send_policy();
}

void QuicPacketGenerator::set_fec_send_policy(FecSendPolicy fec_send_policy) {
  packet_creator_.set_fec_send_policy(fec_send_policy);
}

}  // namespace net
