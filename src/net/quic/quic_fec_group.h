// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Tracks information about an FEC group, including the packets
// that have been seen, and the running parity.  Provides the ability
// to revive a dropped packet.

#ifndef NET_QUIC_QUIC_FEC_GROUP_H_
#define NET_QUIC_QUIC_FEC_GROUP_H_

#include <cstddef>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/quic/quic_fec_group_interface.h"
#include "net/quic/quic_protocol.h"

namespace net {

class NET_EXPORT_PRIVATE QuicFecGroup : public QuicFecGroupInterface {
 public:
  explicit QuicFecGroup(QuicPacketNumber fec_group_number);
  virtual ~QuicFecGroup();

  // Implementation of QuicFecGroupInterface.
  bool Update(EncryptionLevel encryption_level,
              const QuicPacketHeader& header,
              base::StringPiece decrypted_payload) override;
  bool UpdateFec(EncryptionLevel encryption_level,
                 const QuicPacketHeader& header,
                 base::StringPiece redundancy) override;
  bool CanRevive() const override;
  bool IsFinished() const override;
  size_t Revive(QuicPacketHeader* header,
                char* decrypted_payload,
                size_t decrypted_payload_len) override;
  bool IsWaitingForPacketBefore(QuicPacketNumber num) const override;
  const base::StringPiece PayloadParity() const override;
  QuicPacketCount NumReceivedPackets() const override;
  EncryptionLevel EffectiveEncryptionLevel() const override;
  QuicFecGroupNumber FecGroupNumber() const override;

 private:
  bool UpdateParity(base::StringPiece payload);
  // Returns the number of missing packets, or QuicPacketCount max
  // if the number of missing packets is not known.
  QuicPacketCount NumMissingPackets() const;

  bool has_received_fec_packet() const {
    return max_protected_packet_ != kInvalidPacketNumber;
  }

  // Set of packets that we have recevied.
  PacketNumberSet received_packets_;
  // packet number of the first protected packet in this group (the one
  // with the lowest packet number).  Will only be set once the FEC
  // packet has been seen.
  const QuicPacketNumber min_protected_packet_;
  // packet number of the last protected packet in this group (the one
  // with the highest packet number).  Will only be set once the FEC
  // packet has been seen.
  QuicPacketNumber max_protected_packet_;
  // The cumulative parity calculation of all received packets.
  char payload_parity_[kMaxPacketSize];
  size_t payload_parity_len_;
  // The effective encryption level, which is the lowest encryption level of
  // the data and FEC in the group.
  EncryptionLevel effective_encryption_level_;

  DISALLOW_COPY_AND_ASSIGN(QuicFecGroup);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_FEC_GROUP_H_
