// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Cubic algorithm, helper class to TCP cubic.
// For details see http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf.

#ifndef NET_QUIC_CONGESTION_CONTROL_CUBIC_H_
#define NET_QUIC_CONGESTION_CONTROL_CUBIC_H_

#include <stdint.h>

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_connection_stats.h"
#include "net/quic/quic_time.h"

namespace net {

class NET_EXPORT_PRIVATE Cubic {
 public:
  explicit Cubic(const QuicClock* clock);

  void SetNumConnections(int num_connections);

  // Call after a timeout to reset the cubic state.
  void Reset();

  // Compute a new congestion window to use after a loss event.
  // Returns the new congestion window in packets. The new congestion window is
  // a multiplicative decrease of our current window.
  QuicPacketCount CongestionWindowAfterPacketLoss(QuicPacketCount current);

  // Compute a new congestion window to use after a received ACK.
  // Returns the new congestion window in packets. The new congestion window
  // follows a cubic function that depends on the time passed since last
  // packet loss.
  QuicPacketCount CongestionWindowAfterAck(QuicPacketCount current,
                                           QuicTime::Delta delay_min);

  // Call on ack arrival when sender is unable to use the available congestion
  // window. Resets Cubic state during quiescence.
  void OnApplicationLimited();

 private:
  static const QuicTime::Delta MaxCubicTimeInterval() {
    return QuicTime::Delta::FromMilliseconds(30);
  }

  // Compute the TCP Cubic alpha and beta based on the current number of
  // connections.
  float Alpha() const;
  float Beta() const;

  const QuicClock* clock_;

  // Number of connections to simulate.
  int num_connections_;

  // Time when this cycle started, after last loss event.
  QuicTime epoch_;

  // Time when sender went into application-limited period. Zero if not in
  // application-limited period.
  QuicTime app_limited_start_time_;

  // Time when we updated last_congestion_window.
  QuicTime last_update_time_;

  // Last congestion window (in packets) used.
  QuicPacketCount last_congestion_window_;

  // Max congestion window (in packets) used just before last loss event.
  // Note: to improve fairness to other streams an additional back off is
  // applied to this value if the new value is below our latest value.
  QuicPacketCount last_max_congestion_window_;

  // Number of acked packets since the cycle started (epoch).
  QuicPacketCount acked_packets_count_;

  // TCP Reno equivalent congestion window in packets.
  QuicPacketCount estimated_tcp_congestion_window_;

  // Origin point of cubic function.
  QuicPacketCount origin_point_congestion_window_;

  // Time to origin point of cubic function in 2^10 fractions of a second.
  uint32_t time_to_origin_point_;

  // Last congestion window in packets computed by cubic function.
  QuicPacketCount last_target_congestion_window_;

  DISALLOW_COPY_AND_ASSIGN(Cubic);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_CUBIC_H_
