// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_ack_notifier.h"

#include <set>

#include "base/logging.h"
#include "base/stl_util.h"

using base::hash_map;
using std::make_pair;

namespace net {

QuicAckNotifier::PacketInfo::PacketInfo() : packet_payload_size(0) {
}

QuicAckNotifier::PacketInfo::PacketInfo(int payload_size)
    : packet_payload_size(payload_size) {
}

QuicAckNotifier::DelegateInterface::DelegateInterface() {}

QuicAckNotifier::DelegateInterface::~DelegateInterface() {}

QuicAckNotifier::QuicAckNotifier(DelegateInterface* delegate)
    : delegate_(delegate),
      original_packet_count_(0),
      original_byte_count_(0),
      retransmitted_packet_count_(0),
      retransmitted_byte_count_(0) {
  DCHECK(delegate);
}

QuicAckNotifier::~QuicAckNotifier() {
}

void QuicAckNotifier::AddSequenceNumber(
    const QuicPacketSequenceNumber& sequence_number,
    int packet_payload_size) {
  sequence_numbers_.insert(make_pair(sequence_number,
                                     PacketInfo(packet_payload_size)));
  ++original_packet_count_;
  original_byte_count_ += packet_payload_size;
}

bool QuicAckNotifier::OnAck(QuicPacketSequenceNumber sequence_number,
                            QuicTime::Delta delta_largest_observed) {
  DCHECK(ContainsKey(sequence_numbers_, sequence_number));
  sequence_numbers_.erase(sequence_number);
  if (IsEmpty()) {
    // We have seen all the sequence numbers we were waiting for, trigger
    // callback notification.
    delegate_->OnAckNotification(
        original_packet_count_, original_byte_count_,
        retransmitted_packet_count_, retransmitted_byte_count_,
        delta_largest_observed);
    return true;
  }
  return false;
}

void QuicAckNotifier::UpdateSequenceNumber(
    QuicPacketSequenceNumber old_sequence_number,
    QuicPacketSequenceNumber new_sequence_number) {
  DCHECK(!ContainsKey(sequence_numbers_, new_sequence_number));

  PacketInfo packet_info;
  auto it = sequence_numbers_.find(old_sequence_number);
  if (it != sequence_numbers_.end()) {
    packet_info = it->second;
    sequence_numbers_.erase(it);
  } else {
    DLOG(DFATAL) << "Old sequence number not found.";
  }

  ++retransmitted_packet_count_;
  retransmitted_byte_count_ += packet_info.packet_payload_size;
  sequence_numbers_.insert(make_pair(new_sequence_number, packet_info));
}

};  // namespace net
