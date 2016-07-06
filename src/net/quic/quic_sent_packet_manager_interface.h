// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_SENT_PACKET_MANAGER_INTERFACE_H_
#define NET_QUIC_QUIC_SENT_PACKET_MANAGER_INTERFACE_H_

#include "base/macros.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_sustained_bandwidth_recorder.h"

namespace net {

class QuicConfig;
class RttStats;

class NET_EXPORT_PRIVATE QuicSentPacketManagerInterface {
 public:
  // Interface which gets callbacks from the QuicSentPacketManager at
  // interesting points.  Implementations must not mutate the state of
  // the packet manager or connection as a result of these callbacks.
  class NET_EXPORT_PRIVATE DebugDelegate {
   public:
    virtual ~DebugDelegate() {}

    // Called when a spurious retransmission is detected.
    virtual void OnSpuriousPacketRetransmission(
        TransmissionType transmission_type,
        QuicByteCount byte_size) {}

    virtual void OnIncomingAck(const QuicAckFrame& ack_frame,
                               QuicTime ack_receive_time,
                               QuicPacketNumber largest_observed,
                               bool rtt_updated,
                               QuicPacketNumber least_unacked_sent_packet) {}

    virtual void OnPacketLoss(QuicPacketNumber lost_packet_number,
                              TransmissionType transmission_type,
                              QuicTime detection_time) {}
  };

  // Interface which gets callbacks from the QuicSentPacketManager when
  // network-related state changes. Implementations must not mutate the
  // state of the packet manager as a result of these callbacks.
  class NET_EXPORT_PRIVATE NetworkChangeVisitor {
   public:
    virtual ~NetworkChangeVisitor() {}

    // Called when congestion window or RTT may have changed.
    virtual void OnCongestionChange() = 0;

    // Called with the path may be degrading. Note that the path may only be
    // temporarily degrading.
    // TODO(jri): With multipath, this method should probably have a path_id
    // parameter, and should maybe result in the path being marked as inactive.
    virtual void OnPathDegrading() = 0;

    // Called when the Path MTU may have increased.
    virtual void OnPathMtuIncreased(QuicPacketLength packet_size) = 0;
  };

  virtual ~QuicSentPacketManagerInterface() {}

  virtual void SetFromConfig(const QuicConfig& config) = 0;

  // Resumes connection state on the default path.
  virtual void ResumeConnectionState(
      const CachedNetworkParameters& cached_network_params,
      bool max_bandwidth_resumption) = 0;

  // Sets number of active streams of all paths.
  virtual void SetNumOpenStreams(size_t num_streams) = 0;

  // Sets max pacing rate of the default path.
  virtual void SetMaxPacingRate(QuicBandwidth max_pacing_rate) = 0;

  // Indicates the handshake has completed, so no handshake packets need to be
  // retransmitted.
  virtual void SetHandshakeConfirmed() = 0;

  virtual void OnIncomingAck(const QuicAckFrame& ack_frame,
                             QuicTime ack_receive_time) = 0;

  virtual bool IsUnacked(QuicPathId path_id,
                         QuicPacketNumber packet_number) const = 0;

  virtual bool HasRetransmittableFrames(
      QuicPathId path_id,
      QuicPacketNumber packet_number) const = 0;

  // Requests retransmission of all unacked packets of |retransmission_type| on
  // the default path.
  virtual void RetransmitUnackedPackets(
      TransmissionType retransmission_type) = 0;

  // Retransmits the oldest pending packet on the path (on which retransmission
  // alarm fires) if there is still a tail loss probe pending. Invoked after
  // OnRetransmissionTimeout.
  virtual bool MaybeRetransmitTailLossProbe() = 0;

  // Removes the retransmittable frames from all unencrypted packets on the
  // default path to ensure they don't get retransmitted.
  virtual void NeuterUnencryptedPackets() = 0;

  virtual bool HasPendingRetransmissions() const = 0;

  virtual PendingRetransmission NextPendingRetransmission() = 0;

  // Returns true if the default path has unacked packets.
  virtual bool HasUnackedPackets() const = 0;

  virtual QuicPacketNumber GetLeastUnacked(QuicPathId path_id) const = 0;

  virtual bool OnPacketSent(
      SerializedPacket* serialized_packet,
      QuicPathId original_path_id,
      QuicPacketNumber original_packet_number,
      QuicTime sent_time,
      TransmissionType transmission_type,
      HasRetransmittableData has_retransmittable_data) = 0;

  virtual void OnRetransmissionTimeout() = 0;

  // Returns the earliest time we can send the next packet. Sets |path_id| to be
  // the path on which the next packet will be sent.
  virtual QuicTime::Delta TimeUntilSend(QuicTime now,
                                        HasRetransmittableData retransmittable,
                                        QuicPathId* path_id) = 0;

  // Returns the earliest retransmission time of all paths.
  // TODO(fayang): This method should not be const becasue the return value
  // depends upon the time it is invoked.
  virtual const QuicTime GetRetransmissionTime() const = 0;

  // Returns the rtt stats of the default path.
  virtual const RttStats* GetRttStats() const = 0;

  // Returns the estimated bandwidth on default path calculated by the
  // congestion algorithm.
  virtual QuicBandwidth BandwidthEstimate() const = 0;

  // Returns the sustained bandwidth recorder on the default path.
  virtual const QuicSustainedBandwidthRecorder& SustainedBandwidthRecorder()
      const = 0;

  // Returns the size of the current congestion window on default path in number
  // of kDefaultTCPMSS-sized segments.
  virtual QuicPacketCount GetCongestionWindowInTcpMss() const = 0;

  // Determines the number of packets of length |max_packet_length| which fit in
  // the congestion windows for all paths, and returns the max number of packets
  // across all paths.
  virtual QuicPacketCount EstimateMaxPacketsInFlight(
      QuicByteCount max_packet_length) const = 0;

  // Returns the size of the current congestion window size on the default path
  // in bytes.
  virtual QuicByteCount GetCongestionWindowInBytes() const = 0;

  // Returns the size of the slow start congestion window in number of 1460 byte
  // TCP segments on the default path.
  virtual QuicPacketCount GetSlowStartThresholdInTcpMss() const = 0;

  // No longer retransmit data for |stream_id| on all paths.
  virtual void CancelRetransmissionsForStream(QuicStreamId stream_id) = 0;

  // Called when peer address changes and the connection migrates on |path_id|.
  // TODO(fayang): Name of this method is confusing in multipath world because
  // this migration is path level. Need to rename this as OnPeerMigration.
  virtual void OnConnectionMigration(QuicPathId path_id,
                                     PeerAddressChangeType type) = 0;

  virtual bool IsHandshakeConfirmed() const = 0;

  virtual void SetDebugDelegate(DebugDelegate* debug_delegate) = 0;

  virtual QuicPacketNumber GetLargestObserved(QuicPathId path_id) const = 0;

  virtual QuicPacketNumber GetLargestSentPacket(QuicPathId path_id) const = 0;

  virtual QuicPacketNumber GetLeastPacketAwaitedByPeer(
      QuicPathId path_id) const = 0;

  virtual void SetNetworkChangeVisitor(NetworkChangeVisitor* visitor) = 0;

  // Returns true if the default path is in slow start.
  virtual bool InSlowStart() const = 0;

  // These two methods return the consecutive RTO or TLP count of the default
  // path.
  virtual size_t GetConsecutiveRtoCount() const = 0;
  virtual size_t GetConsecutiveTlpCount() const = 0;
};

}  // namespace net

#endif  // NET_QUIC_QUIC_SENT_PACKET_MANAGER_INTERFACE_H_
