// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Tracks information about an FEC group, including the packets
// that have been seen, and the running parity.  Provides the ability
// to revive a dropped packet.

#ifndef NET_QUIC_QUIC_FEC_GROUP_INTERFACE_H_
#define NET_QUIC_QUIC_FEC_GROUP_INTERFACE_H_

#include <stddef.h>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"

namespace net {

class NET_EXPORT_PRIVATE QuicFecGroupInterface {
 public:
  ~QuicFecGroupInterface() {}

  // Updates the FEC group based on the delivery of a data packet decrypted at
  // |encryption_level|. Returns false if this packet has already been seen,
  // true otherwise.
  virtual bool Update(EncryptionLevel encryption_level,
                      const QuicPacketHeader& header,
                      base::StringPiece decrypted_payload) = 0;

  // Updates the FEC group based on the delivery of an FEC packet decrypted at
  // |encryption_level|. Returns false if this packet has already been seen or
  // if it does not claim to protect all the packets previously seen in this
  // group.
  virtual bool UpdateFec(EncryptionLevel encryption_level,
                         const QuicPacketHeader& header,
                         base::StringPiece redundancy) = 0;

  // Returns true if a packet can be revived from this FEC group.
  virtual bool CanRevive() const = 0;

  // Returns true if all packets (FEC and data) from this FEC group have been
  // seen or revived.
  virtual bool IsFinished() const = 0;

  // Revives the missing packet from this FEC group.  This may return a packet
  // that is null padded to a greater length than the original packet, but
  // the framer will handle it correctly.  Returns the length of the data
  // written to |decrypted_payload|, or 0 if the packet could not be revived.
  virtual size_t Revive(QuicPacketHeader* header,
                        char* decrypted_payload,
                        size_t decrypted_payload_len) = 0;

  // Returns true if the group is waiting for any packets with sequence numbers
  // less than |num|.
  virtual bool IsWaitingForPacketBefore(QuicPacketNumber num) const = 0;

  // The FEC data in the FEC packet.
  virtual const base::StringPiece PayloadParity() const = 0;

  // Number of packets in the group.
  virtual QuicPacketCount NumReceivedPackets() const = 0;

  // Returns the effective encryption level of the FEC group.
  virtual EncryptionLevel EffectiveEncryptionLevel() const = 0;

  // Return the FEC group number of this group.
  virtual QuicFecGroupNumber FecGroupNumber() const = 0;

  // An optimized version of running |output| ^= |input|, where ^ is
  // byte-by-byte XOR and both |output| and |input| are of size |size_in_bytes|.
  static void XorBuffers(const char* input, size_t size_in_bytes, char* output);

 protected:
  QuicFecGroupInterface() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicFecGroupInterface);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_FEC_GROUP_INTERFACE_H_
