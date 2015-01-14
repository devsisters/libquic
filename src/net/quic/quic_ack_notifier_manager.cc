// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_ack_notifier_manager.h"

#include <stddef.h>
#include <list>
#include <map>
#include <utility>
#include <vector>

#include "base/stl_util.h"
#include "net/quic/quic_ack_notifier.h"
#include "net/quic/quic_protocol.h"

namespace net {

AckNotifierManager::AckNotifierManager() {}

AckNotifierManager::~AckNotifierManager() {
  STLDeleteElements(&ack_notifiers_);
}

void AckNotifierManager::OnPacketAcked(QuicPacketSequenceNumber sequence_number,
                                       QuicTime::Delta delta_largest_observed) {
  // Inform all the registered AckNotifiers of the new ACK.
  auto map_it = ack_notifier_map_.find(sequence_number);
  if (map_it == ack_notifier_map_.end()) {
    // No AckNotifier is interested in this sequence number.
    return;
  }

  // One or more AckNotifiers are registered as interested in this sequence
  // number. Iterate through them and call OnAck on each.
  AckNotifierSet& ack_notifier_set = map_it->second;
  for (QuicAckNotifier* ack_notifier : ack_notifier_set) {
    ack_notifier->OnAck(sequence_number, delta_largest_observed);

    // If this has resulted in an empty AckNotifer, erase it.
    if (ack_notifier->IsEmpty()) {
      delete ack_notifier;
      ack_notifiers_.erase(ack_notifier);
    }
  }

  // Remove the sequence number from the map as we have notified all the
  // registered AckNotifiers, and we won't see it again.
  ack_notifier_map_.erase(map_it);
}

void AckNotifierManager::UpdateSequenceNumber(
    QuicPacketSequenceNumber old_sequence_number,
    QuicPacketSequenceNumber new_sequence_number) {
  auto map_it = ack_notifier_map_.find(old_sequence_number);
  if (map_it == ack_notifier_map_.end()) {
    // No AckNotifiers are interested in the old sequence number.
    return;
  }

  // Update the existing QuicAckNotifiers to the new sequence number.
  AckNotifierSet& ack_notifier_set = map_it->second;
  for (QuicAckNotifier* ack_notifier : ack_notifier_set) {
    ack_notifier->UpdateSequenceNumber(old_sequence_number,
                                       new_sequence_number);
  }

  // The old sequence number is no longer of interest, copy the updated
  // AckNotifiers to the new sequence number before deleting the old.
  ack_notifier_map_[new_sequence_number] = ack_notifier_set;
  ack_notifier_map_.erase(map_it);
}

void AckNotifierManager::OnSerializedPacket(
    const SerializedPacket& serialized_packet) {
  // AckNotifiers can only be attached to retransmittable frames.
  RetransmittableFrames* frames = serialized_packet.retransmittable_frames;
  if (frames == nullptr) {
    return;
  }

  // For each frame in |serialized_packet|, inform any attached AckNotifiers of
  // the packet's sequence number.
  for (const QuicFrame& quic_frame : frames->frames()) {
    if (quic_frame.type != STREAM_FRAME ||
        quic_frame.stream_frame->notifier == nullptr) {
      continue;
    }

    QuicAckNotifier* notifier = quic_frame.stream_frame->notifier;
    notifier->AddSequenceNumber(serialized_packet.sequence_number,
                                serialized_packet.packet->length());

    // Update the mapping in the other direction, from sequence number to
    // AckNotifier.
    ack_notifier_map_[serialized_packet.sequence_number].insert(notifier);

    // Take ownership of the AckNotifier.
    ack_notifiers_.insert(notifier);
  }
}

}  // namespace net
