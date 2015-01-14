// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This class is a helper class to TcpCubicSender.
// Slow start is the initial startup phase of TCP, it lasts until first packet
// loss. This class implements hybrid slow start of the TCP cubic send side
// congestion algorithm. The key feaure of hybrid slow start is that it tries to
// avoid running into the wall too hard during the slow start phase, which
// the traditional TCP implementation does.
// http://netsrv.csc.ncsu.edu/export/hybridstart_pfldnet08.pdf
// http://research.csc.ncsu.edu/netsrv/sites/default/files/hystart_techreport_2008.pdf

#ifndef NET_QUIC_CONGESTION_CONTROL_HYBRID_SLOW_START_H_
#define NET_QUIC_CONGESTION_CONTROL_HYBRID_SLOW_START_H_

#include "base/basictypes.h"
#include "net/base/net_export.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

class NET_EXPORT_PRIVATE HybridSlowStart {
 public:
  explicit HybridSlowStart(const QuicClock* clock);

  void OnPacketAcked(QuicPacketSequenceNumber acked_sequence_number,
                     bool in_slow_start);

  void OnPacketSent(QuicPacketSequenceNumber sequence_number);

  // ShouldExitSlowStart should be called on every new ack frame, since a new
  // RTT measurement can be made then.
  // rtt: the RTT for this ack packet.
  // min_rtt: is the lowest delay (RTT) we have seen during the session.
  // congestion_window: the congestion window in packets.
  bool ShouldExitSlowStart(QuicTime::Delta rtt,
                           QuicTime::Delta min_rtt,
                           int64 congestion_window);

  // Start a new slow start phase.
  void Restart();

  // TODO(ianswett): The following methods should be private, but that requires
  // a follow up CL to update the unit test.
  // Returns true if this ack the last sequence number of our current slow start
  // round.
  // Call Reset if this returns true.
  bool IsEndOfRound(QuicPacketSequenceNumber ack) const;

  // Call for the start of each receive round (burst) in the slow start phase.
  void StartReceiveRound(QuicPacketSequenceNumber last_sent);

  void set_ack_train_detection(bool ack_train_detection) {
    ack_train_detection_ = ack_train_detection;
  }

  bool ack_train_detection() const {
    return ack_train_detection_;
  }

  // Whether slow start has started.
  bool started() const {
    return started_;
  }

 private:
  // Whether a condition for exiting slow start has been found.
  enum HystartState {
    NOT_FOUND,
    ACK_TRAIN,  // A closely spaced ack train is too long.
    DELAY,  // Too much increase in the round's min_rtt was observed.
  };

  const QuicClock* clock_;
  bool ack_train_detection_;
  // Whether the hybrid slow start has been started.
  bool started_;
  HystartState hystart_found_;
  // Last sequence number sent which was CWND limited.
  QuicPacketSequenceNumber last_sent_sequence_number_;

  // Variables for tracking acks received during a slow start round.
  QuicTime round_start_;  // Beginning of each slow start receive round.
  QuicPacketSequenceNumber end_sequence_number_;  // End of the receive round.
  // Last time when the spacing between ack arrivals was less than 2 ms.
  // Defaults to the beginning of the round.
  QuicTime last_close_ack_pair_time_;
  uint32 rtt_sample_count_;  // Number of rtt samples in the current round.
  QuicTime::Delta current_min_rtt_;  // The minimum rtt of current round.

  DISALLOW_COPY_AND_ASSIGN(HybridSlowStart);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_HYBRID_SLOW_START_H_
