// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_fec_group.h"

#include <limits>

#include "base/logging.h"
#include "base/stl_util.h"

using base::StringPiece;
using std::numeric_limits;
using std::set;

namespace net {

QuicFecGroup::QuicFecGroup(QuicPacketNumber fec_group_number)
    : QuicFecGroupInterface(),
      min_protected_packet_(fec_group_number),
      max_protected_packet_(kInvalidPacketNumber),
      payload_parity_len_(0),
      effective_encryption_level_(NUM_ENCRYPTION_LEVELS) {}

QuicFecGroup::~QuicFecGroup() {}

bool QuicFecGroup::Update(EncryptionLevel encryption_level,
                          const QuicPacketHeader& header,
                          StringPiece decrypted_payload) {
  DCHECK_EQ(min_protected_packet_, header.fec_group);
  DCHECK_NE(kInvalidPacketNumber, header.packet_number);
  if (ContainsKey(received_packets_, header.packet_number)) {
    return false;
  }
  if (header.packet_number < min_protected_packet_ ||
      (has_received_fec_packet() &&
       header.packet_number > max_protected_packet_)) {
    DLOG(ERROR) << "FEC group does not cover received packet: "
                << header.packet_number;
    return false;
  }
  if (!UpdateParity(decrypted_payload)) {
    return false;
  }
  received_packets_.insert(header.packet_number);
  if (encryption_level < effective_encryption_level_) {
    effective_encryption_level_ = encryption_level;
  }
  return true;
}

bool QuicFecGroup::UpdateFec(EncryptionLevel encryption_level,
                             const QuicPacketHeader& header,
                             StringPiece redundancy) {
  DCHECK_EQ(min_protected_packet_, header.fec_group);
  DCHECK_NE(kInvalidPacketNumber, header.packet_number);
  if (has_received_fec_packet()) {
    return false;
  }
  for (QuicPacketNumber packet : received_packets_) {
    if (packet >= header.packet_number) {
      DLOG(ERROR) << "FEC group does not cover received packet: " << packet;
      return false;
    }
  }
  if (!UpdateParity(redundancy)) {
    return false;
  }
  max_protected_packet_ = header.packet_number - 1;
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

  // Identify the packet number to be resurrected.
  QuicPacketNumber missing = kInvalidPacketNumber;
  for (QuicPacketNumber i = min_protected_packet_; i <= max_protected_packet_;
       ++i) {
    // Is this packet missing?
    if (received_packets_.count(i) == 0) {
      missing = i;
      break;
    }
  }
  DCHECK_NE(kInvalidPacketNumber, missing);

  DCHECK_LE(payload_parity_len_, decrypted_payload_len);
  if (payload_parity_len_ > decrypted_payload_len) {
    return 0;
  }
  for (size_t i = 0; i < payload_parity_len_; ++i) {
    decrypted_payload[i] = payload_parity_[i];
  }

  header->packet_number = missing;
  header->entropy_flag = false;  // Unknown entropy.

  received_packets_.insert(missing);
  return payload_parity_len_;
}

bool QuicFecGroup::IsWaitingForPacketBefore(QuicPacketNumber num) const {
  // Entire range is larger than the threshold.
  if (min_protected_packet_ >= num) {
    return false;
  }

  // Entire range is smaller than the threshold.
  if (received_packets_.size() > 0 ? *received_packets_.rbegin() + 1 < num
                                   : min_protected_packet_ < num) {
    return true;
  }

  // Range spans the threshold so look for a missing packet below the threshold.
  QuicPacketNumber target = min_protected_packet_;
  for (QuicPacketNumber packet : received_packets_) {
    if (target++ != packet) {
      return true;
    }
    if (target >= num) {
      return false;
    }
  }

  // No missing packets below the threshold.
  return false;
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
  if (received_packets_.empty() && !has_received_fec_packet()) {
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
  XorBuffers(payload.data(), payload.size(), payload_parity_);
  return true;
}

QuicPacketCount QuicFecGroup::NumMissingPackets() const {
  if (!has_received_fec_packet()) {
    return numeric_limits<QuicPacketCount>::max();
  }
  return static_cast<QuicPacketCount>(
      (max_protected_packet_ - min_protected_packet_ + 1) -
      received_packets_.size());
}

const StringPiece QuicFecGroup::PayloadParity() const {
  return StringPiece(payload_parity_, payload_parity_len_);
}

QuicPacketCount QuicFecGroup::NumReceivedPackets() const {
  return received_packets_.size();
}

EncryptionLevel QuicFecGroup::EffectiveEncryptionLevel() const {
  return effective_encryption_level_;
}

QuicFecGroupNumber QuicFecGroup::FecGroupNumber() const {
  return min_protected_packet_;
}

}  // namespace net
