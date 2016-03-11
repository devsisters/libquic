// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CONGESTION_CONTROL_GENERAL_LOSS_ALGORITHM_H_
#define NET_QUIC_CONGESTION_CONTROL_GENERAL_LOSS_ALGORITHM_H_

#include <algorithm>
#include <map>

#include "base/macros.h"
#include "net/quic/congestion_control/loss_detection_interface.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"
#include "net/quic/quic_unacked_packet_map.h"

namespace net {

// Class which can be configured to implement's TCP's approach of detecting loss
// when 3 nacks have been received for a packet or with a time threshold.
// Also implements TCP's early retransmit(RFC5827).
class NET_EXPORT_PRIVATE GeneralLossAlgorithm : public LossDetectionInterface {
 public:
  // TCP retransmits after 3 nacks.
  static const QuicPacketCount kNumberOfNacksBeforeRetransmission = 3;

  GeneralLossAlgorithm();
  explicit GeneralLossAlgorithm(LossDetectionType loss_type);
  ~GeneralLossAlgorithm() override {}

  LossDetectionType GetLossDetectionType() const override;
  void SetLossDetectionType(LossDetectionType loss_type) {
    loss_type_ = loss_type;
  }

  // Uses |largest_observed| and time to decide when packets are lost.
  void DetectLosses(
      const QuicUnackedPacketMap& unacked_packets,
      const QuicTime& time,
      const RttStats& rtt_stats,
      SendAlgorithmInterface::CongestionVector* packets_lost) override;

  // Returns a non-zero value when the early retransmit timer is active.
  QuicTime GetLossTimeout() const override;

 private:
  LossDetectionType loss_type_;
  QuicTime loss_detection_timeout_;

  DISALLOW_COPY_AND_ASSIGN(GeneralLossAlgorithm);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_GENERAL_LOSS_ALGORITHM_H_
