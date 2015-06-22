// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_fec_group.h"

#include <limits>

#include "base/basictypes.h"
#include "base/logging.h"
#include "base/stl_util.h"

using base::StringPiece;
using std::numeric_limits;
using std::set;

namespace net {

QuicFecGroup::QuicFecGroup()
    : min_protected_packet_(kInvalidPacketSequenceNumber),
      max_protected_packet_(kInvalidPacketSequenceNumber),
      payload_parity_len_(0),
      effective_encryption_level_(NUM_ENCRYPTION_LEVELS) {
}

QuicFecGroup::~QuicFecGroup() {}

bool QuicFecGroup::Update(EncryptionLevel encryption_level,
                          const QuicPacketHeader& header,
                          StringPiece decrypted_payload) {
  DCHECK_NE(kInvalidPacketSequenceNumber, header.packet_sequence_number);
  if (ContainsKey(received_packets_, header.packet_sequence_number)) {
    return false;
  }
  if (min_protected_packet_ != kInvalidPacketSequenceNumber &&
      max_protected_packet_ != kInvalidPacketSequenceNumber &&
      (header.packet_sequence_number < min_protected_packet_ ||
       header.packet_sequence_number > max_protected_packet_)) {
    DLOG(ERROR) << "FEC group does not cover received packet: "
                << header.packet_sequence_number;
    return false;
  }
  if (!UpdateParity(decrypted_payload)) {
    return false;
  }
  received_packets_.insert(header.packet_sequence_number);
  if (encryption_level < effective_encryption_level_) {
    effective_encryption_level_ = encryption_level;
  }
  return true;
}

bool QuicFecGroup::UpdateFec(
    EncryptionLevel encryption_level,
    QuicPacketSequenceNumber fec_packet_sequence_number,
    const QuicFecData& fec) {
  DCHECK_NE(kInvalidPacketSequenceNumber, fec_packet_sequence_number);
  DCHECK_NE(kInvalidPacketSequenceNumber, fec.fec_group);
  if (min_protected_packet_ != kInvalidPacketSequenceNumber) {
    return false;
  }
  SequenceNumberSet::const_iterator it = received_packets_.begin();
  while (it != received_packets_.end()) {
    if ((*it < fec.fec_group) || (*it >= fec_packet_sequence_number)) {
      DLOG(ERROR) << "FEC group does not cover received packet: " << *it;
      return false;
    }
    ++it;
  }
  if (!UpdateParity(fec.redundancy)) {
    return false;
  }
  min_protected_packet_ = fec.fec_group;
  max_protected_packet_ = fec_packet_sequence_number - 1;
  if (encryption_level < effective_encryption_level_) {
    effective_encryption_level_ = encryption_level;
  }
  return true;
}

bool QuicFecGroup::CanRevive() const {
  // We can revive if we're missing exactly 1 packet.
  return NumMissingPackets() == 1;
}

bool QuicFecGroup::IsFinished() const {
  // We are finished if we are not missing any packets.
  return NumMissingPackets() == 0;
}

size_t QuicFecGroup::Revive(QuicPacketHeader* header,
                            char* decrypted_payload,
                            size_t decrypted_payload_len) {
  if (!CanRevive()) {
    return 0;
  }

  // Identify the packet sequence number to be resurrected.
  QuicPacketSequenceNumber missing = kInvalidPacketSequenceNumber;
  for (QuicPacketSequenceNumber i = min_protected_packet_;
       i <= max_protected_packet_; ++i) {
    // Is this packet missing?
    if (received_packets_.count(i) == 0) {
      missing = i;
      break;
    }
  }
  DCHECK_NE(kInvalidPacketSequenceNumber, missing);

  DCHECK_LE(payload_parity_len_, decrypted_payload_len);
  if (payload_parity_len_ > decrypted_payload_len) {
    return 0;
  }
  for (size_t i = 0; i < payload_parity_len_; ++i) {
    decrypted_payload[i] = payload_parity_[i];
  }

  header->packet_sequence_number = missing;
  header->entropy_flag = false;  // Unknown entropy.

  received_packets_.insert(missing);
  return payload_parity_len_;
}

bool QuicFecGroup::ProtectsPacketsBefore(QuicPacketSequenceNumber num) const {
  if (max_protected_packet_ != kInvalidPacketSequenceNumber) {
    return max_protected_packet_ < num;
  }
  // Since we might not yet have received the FEC packet, we must check
  // the packets we have received.
  return *received_packets_.begin() < num;
}

bool QuicFecGroup::UpdateParity(StringPiece payload) {
  DCHECK_GE(kMaxPacketSize, payload.size());
  if (payload.size() > kMaxPacketSize) {
    DLOG(ERROR) << "Illegal payload size: " << payload.size();
    return false;
  }
  if (payload_parity_len_ < payload.size()) {
    payload_parity_len_ = payload.size();
  }
  if (received_packets_.empty() &&
      min_protected_packet_ == kInvalidPacketSequenceNumber) {
    // Initialize the parity to the value of this payload
    memcpy(payload_parity_, payload.data(), payload.size());
    if (payload.size() < kMaxPacketSize) {
      // TODO(rch): expand as needed.
      memset(payload_parity_ + payload.size(), 0,
             kMaxPacketSize - payload.size());
    }
    return true;
  }
  // Update the parity by XORing in the data (padding with 0s if necessary).
  for (size_t i = 0; i < kMaxPacketSize; ++i) {
    uint8 byte = i < payload.size() ? payload[i] : 0x00;
    payload_parity_[i] ^= byte;
  }
  return true;
}

QuicPacketCount QuicFecGroup::NumMissingPackets() const {
  if (min_protected_packet_ == kInvalidPacketSequenceNumber) {
    return numeric_limits<QuicPacketCount>::max();
  }
  return static_cast<QuicPacketCount>(
      (max_protected_packet_ - min_protected_packet_ + 1) -
      received_packets_.size());
}

}  // namespace net
