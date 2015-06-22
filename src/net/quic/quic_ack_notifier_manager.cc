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
#include "net/quic/quic_flags.h"
#include "net/quic/quic_protocol.h"

namespace net {

AckNotifierManager::AckNotifierManager() {}

AckNotifierManager::~AckNotifierManager() {
  for (const auto& pair : ack_notifier_map_) {
    for (QuicAckNotifier* notifier : pair.second) {
      if (notifier->OnPacketAbandoned()) {
        delete notifier;
      }
    }
  }
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
  for (QuicAckNotifier* ack_notifier : map_it->second) {
    if (ack_notifier->OnAck(delta_largest_observed)) {
      // If this has resulted in an empty AckNotifer, erase it.
      delete ack_notifier;
    }
  }

  // Remove the sequence number from the map as we have notified all the
  // registered AckNotifiers, and we won't see it again.
  ack_notifier_map_.erase(map_it);
}

void AckNotifierManager::OnPacketRetransmitted(
    QuicPacketSequenceNumber old_sequence_number,
    QuicPacketSequenceNumber new_sequence_number,
    int packet_payload_size) {
  auto map_it = ack_notifier_map_.find(old_sequence_number);
  if (map_it == ack_notifier_map_.end()) {
    // No AckNotifiers are interested in the old sequence number.
    return;
  }

  // Update the existing QuicAckNotifiers to the new sequence number.
  AckNotifierList& ack_notifier_list = map_it->second;
  for (QuicAckNotifier* ack_notifier : ack_notifier_list) {
    ack_notifier->OnPacketRetransmitted(packet_payload_size);
  }

  // The old sequence number is no longer of interest, copy the updated
  // AckNotifiers to the new sequence number before deleting the old.
  ack_notifier_map_[new_sequence_number] = ack_notifier_list;
  ack_notifier_map_.erase(map_it);
}

void AckNotifierManager::OnSerializedPacket(
    const SerializedPacket& serialized_packet) {
  // Inform each attached AckNotifier of the packet's serialization.
  AckNotifierList& notifier_list =
      ack_notifier_map_[serialized_packet.sequence_number];
  for (QuicAckNotifier* notifier : serialized_packet.notifiers) {
    if (notifier == nullptr) {
      LOG(DFATAL) << "AckNotifier should not be nullptr.";
      continue;
    }
    notifier->OnSerializedPacket();
    notifier_list.push_back(notifier);
  }
}

}  // namespace net
