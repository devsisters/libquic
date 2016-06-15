// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The pure virtual class for send side congestion control algorithm.

#ifndef NET_QUIC_CONGESTION_CONTROL_SEND_ALGORITHM_INTERFACE_H_
#define NET_QUIC_CONGESTION_CONTROL_SEND_ALGORITHM_INTERFACE_H_

#include <algorithm>
#include <map>

#include "net/base/net_export.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_connection_stats.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

class CachedNetworkParameters;
class RttStats;

const QuicPacketCount kDefaultMaxCongestionWindowPackets = 2000;

class NET_EXPORT_PRIVATE SendAlgorithmInterface {
 public:
  // A sorted vector of packets.
  typedef std::vector<std::pair<QuicPacketNumber, QuicPacketLength>>
      CongestionVector;

  static SendAlgorithmInterface* Create(
      const QuicClock* clock,
      const RttStats* rtt_stats,
      CongestionControlType type,
      QuicConnectionStats* stats,
      QuicPacketCount initial_congestion_window);

  virtual ~SendAlgorithmInterface() {}

  virtual void SetFromConfig(const QuicConfig& config,
                             Perspective perspective) = 0;

  // Sets the number of connections to emulate when doing congestion control,
  // particularly for congestion avoidance.  Can be set any time.
  virtual void SetNumEmulatedConnections(int num_connections) = 0;

  // Sets the maximum congestion window in bytes.
  virtual void SetMaxCongestionWindow(QuicByteCount max_congestion_window) = 0;

  // Indicates an update to the congestion state, caused either by an incoming
  // ack or loss event timeout.  |rtt_updated| indicates whether a new
  // latest_rtt sample has been taken, |byte_in_flight| the bytes in flight
  // prior to the congestion event.  |acked_packets| and |lost_packets| are
  // any packets considered acked or lost as a result of the congestion event.
  virtual void OnCongestionEvent(bool rtt_updated,
                                 QuicByteCount bytes_in_flight,
                                 const CongestionVector& acked_packets,
                                 const CongestionVector& lost_packets) = 0;

  // Inform that we sent |bytes| to the wire, and if the packet is
  // retransmittable. Returns true if the packet should be tracked by the
  // congestion manager and included in bytes_in_flight, false otherwise.
  // |bytes_in_flight| is the number of bytes in flight before the packet was
  // sent.
  // Note: this function must be called for every packet sent to the wire.
  virtual bool OnPacketSent(QuicTime sent_time,
                            QuicByteCount bytes_in_flight,
                            QuicPacketNumber packet_number,
                            QuicByteCount bytes,
                            HasRetransmittableData is_retransmittable) = 0;

  // Called when the retransmission timeout fires.  Neither OnPacketAbandoned
  // nor OnPacketLost will be called for these packets.
  virtual void OnRetransmissionTimeout(bool packets_retransmitted) = 0;

  // Called when connection migrates and cwnd needs to be reset.
  virtual void OnConnectionMigration() = 0;

  // Calculate the time until we can send the next packet.
  virtual QuicTime::Delta TimeUntilSend(
      QuicTime now,
      QuicByteCount bytes_in_flight) const = 0;

  // The pacing rate of the send algorithm.  May be zero if the rate is unknown.
  virtual QuicBandwidth PacingRate(QuicByteCount bytes_in_flight) const = 0;

  // What's the current estimated bandwidth in bytes per second.
  // Returns 0 when it does not have an estimate.
  virtual QuicBandwidth BandwidthEstimate() const = 0;

  // Get the send algorithm specific retransmission delay, called RTO in TCP,
  // Note 1: the caller is responsible for sanity checking this value.
  // Note 2: this will return zero if we don't have enough data for an estimate.
  virtual QuicTime::Delta RetransmissionDelay() const = 0;

  // Returns the size of the current congestion window in bytes.  Note, this is
  // not the *available* window.  Some send algorithms may not use a congestion
  // window and will return 0.
  virtual QuicByteCount GetCongestionWindow() const = 0;

  // Whether the send algorithm is currently in slow start.  When true, the
  // BandwidthEstimate is expected to be too low.
  virtual bool InSlowStart() const = 0;

  // Whether the send algorithm is currently in recovery.
  virtual bool InRecovery() const = 0;

  // Returns the size of the slow start congestion window in bytes,
  // aka ssthresh.  Some send algorithms do not define a slow start
  // threshold and will return 0.
  virtual QuicByteCount GetSlowStartThreshold() const = 0;

  virtual CongestionControlType GetCongestionControlType() const = 0;

  // Called by the Session when we get a bandwidth estimate from the client.
  // Uses the max bandwidth in the params if |max_bandwidth_resumption| is true.
  virtual void ResumeConnectionState(
      const CachedNetworkParameters& cached_network_params,
      bool max_bandwidth_resumption) = 0;
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_SEND_ALGORITHM_INTERFACE_H_
