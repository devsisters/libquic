// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The pure virtual class for send side loss detection algorithm.

#ifndef NET_QUIC_CONGESTION_CONTROL_LOSS_DETECTION_INTERFACE_H_
#define NET_QUIC_CONGESTION_CONTROL_LOSS_DETECTION_INTERFACE_H_

#include "net/quic/congestion_control/send_algorithm_interface.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

class QuicUnackedPacketMap;
class RttStats;

class NET_EXPORT_PRIVATE LossDetectionInterface {
 public:
  // Creates a TCP loss detector.
  static LossDetectionInterface* Create(LossDetectionType loss_type);

  virtual ~LossDetectionInterface() {}

  virtual LossDetectionType GetLossDetectionType() const = 0;

  // Called when a new ack arrives or the loss alarm fires.
  virtual void DetectLosses(
      const QuicUnackedPacketMap& unacked_packets,
      const QuicTime& time,
      const RttStats& rtt_stats,
      SendAlgorithmInterface::CongestionVector* packets_lost) = 0;

  // Get the time the LossDetectionAlgorithm wants to re-evaluate losses.
  // Returns QuicTime::Zero if no alarm needs to be set.
  virtual QuicTime GetLossTimeout() const = 0;
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_LOSS_DETECTION_INTERFACE_H_
