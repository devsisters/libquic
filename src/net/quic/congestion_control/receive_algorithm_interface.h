// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The pure virtual class for receive side congestion algorithm.

#ifndef NET_QUIC_CONGESTION_CONTROL_RECEIVE_ALGORITHM_INTERFACE_H_
#define NET_QUIC_CONGESTION_CONTROL_RECEIVE_ALGORITHM_INTERFACE_H_

#include "base/basictypes.h"
#include "net/base/net_export.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

class NET_EXPORT_PRIVATE ReceiveAlgorithmInterface {
 public:
  static ReceiveAlgorithmInterface* Create(CongestionFeedbackType type);

  virtual ~ReceiveAlgorithmInterface() {}

  // Returns false if no QuicCongestionFeedbackFrame block is needed.
  // Otherwise fills in feedback and return true.
  virtual bool GenerateCongestionFeedback(
      QuicCongestionFeedbackFrame* feedback) = 0;

  // Should be called for each incoming packet.
  // bytes: is the packet size in bytes including IP headers.
  // sequence_number: is the unique sequence number from the QUIC packet header.
  // timestamp: is the sent timestamp from the QUIC packet header.
  virtual void RecordIncomingPacket(QuicByteCount bytes,
                                    QuicPacketSequenceNumber sequence_number,
                                    QuicTime timestamp) = 0;
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_RECEIVE_ALGORITHM_INTERFACE_H_
