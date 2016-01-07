// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CONGESTION_CONTROL_TIME_LOSS_ALGORITHM_H_
#define NET_QUIC_CONGESTION_CONTROL_TIME_LOSS_ALGORITHM_H_

#include <algorithm>
#include <map>

#include "base/macros.h"
#include "net/quic/congestion_control/loss_detection_interface.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"
#include "net/quic/quic_unacked_packet_map.h"

namespace net {

// A loss detection algorithm which avoids spurious losses and retransmissions
// by waiting 1.25 RTTs after a packet was sent instead of nack count.
class NET_EXPORT_PRIVATE TimeLossAlgorithm : public LossDetectionInterface {
 public:
  TimeLossAlgorithm();
  ~TimeLossAlgorithm() override {}

  LossDetectionType GetLossDetectionType() const override;

  // Declares pending packets less than the largest observed lost when it has
  // been 1.25 RTT since they were sent.  Packets larger than the largest
  // observed are retransmitted via TLP.
  PacketNumberSet DetectLostPackets(const QuicUnackedPacketMap& unacked_packets,
                                    const QuicTime& time,
                                    QuicPacketNumber largest_observed,
                                    const RttStats& rtt_stats) override;

  // Unsupported.
  void DetectLosses(
      const QuicUnackedPacketMap& unacked_packets,
      const QuicTime& time,
      const RttStats& rtt_stats,
      SendAlgorithmInterface::CongestionVector* packets_lost) override;

  // Returns the time the next packet will be lost, or zero if there
  // are no nacked pending packets outstanding.
  // TODO(ianswett): Ideally the RTT variance and the RTT would be used to
  // determine the time a packet is considered lost.
  // TODO(ianswett): Consider using Max(1.25 * srtt, 1.125 * last_rtt).
  QuicTime GetLossTimeout() const override;

 private:
  QuicTime loss_detection_timeout_;

  DISALLOW_COPY_AND_ASSIGN(TimeLossAlgorithm);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_TIME_LOSS_ALGORITHM_H_
