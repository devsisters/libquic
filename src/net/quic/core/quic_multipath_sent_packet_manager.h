// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_MULTIPATH_SENT_PACKET_MANAGER_H_
#define NET_QUIC_QUIC_MULTIPATH_SENT_PACKET_MANAGER_H_

#include <vector>

#include "net/base/net_export.h"
#include "net/quic/core/quic_protocol.h"
#include "net/quic/core/quic_sent_packet_manager.h"
#include "net/quic/core/quic_sent_packet_manager_interface.h"

namespace net {

namespace test {
class QuicConnectionPeer;
class QuicMultipathSentPacketManagerPeer;
}  // namespace test

// A connection level sent packet manager which manages a sent packet manager
// per path. The main duties of multipath sent packet manager comprise:
// (1) manages a pending retransmission queue shared among all paths;
// (2) records mapping of packets transmitted on different paths;
// (3) consults paths which should timeout on a retransmission timeout.
// TODO(fayang): Currently above duties are not fully implemented, need to
// finish them.
class NET_EXPORT_PRIVATE QuicMultipathSentPacketManager
    : public QuicSentPacketManagerInterface {
 public:
  // Multipath sent packet manager takes ownership of |manager|.
  explicit QuicMultipathSentPacketManager(
      QuicSentPacketManagerInterface* manager,
      QuicConnectionCloseDelegateInterface* delegate);
  ~QuicMultipathSentPacketManager() override;

  // Start implementation of QuicSentPacketManagerInterface.
  // Sets all paths from |config|.
  void SetFromConfig(const QuicConfig& config) override;

  // Resumes connection state on the default path.
  void ResumeConnectionState(
      const CachedNetworkParameters& cached_network_params,
      bool max_bandwidth_resumption) override;

  // Sets number of active streams of all paths.
  void SetNumOpenStreams(size_t num_streams) override;

  // Sets max pacing rate of the default path.
  void SetMaxPacingRate(QuicBandwidth max_pacing_rate) override;

  void SetHandshakeConfirmed() override;

  // Directs |ack_frame| to the appropriate path sent packet manager.
  void OnIncomingAck(const QuicAckFrame& ack_frame,
                     QuicTime ack_receive_time) override;

  // Requests retransmission of all unacked packets of |retransmission_type| on
  // the default path.
  void RetransmitUnackedPackets(TransmissionType retransmission_type) override;

  // Tries to retransmit the oldest pending packet across all paths. The
  // retransmission is sent on the path that has a TLP timer pending.
  bool MaybeRetransmitTailLossProbe() override;

  // Removes the retransmittable frames from all unencrypted packets on the
  // default path to ensure they don't get retransmitted.
  void NeuterUnencryptedPackets() override;

  // Returns true if there are pending retransmissions.
  bool HasPendingRetransmissions() const override;

  // Retrieves the next pending retransmission.  Caller must ensure that
  // there are pending retransmissions prior to calling this function.
  PendingRetransmission NextPendingRetransmission() override;

  // Returns true if the any path has unacked packets.
  bool HasUnackedPackets() const override;

  // Returns the smallest packet number of a serialized packet which has not
  // been acked on |path_id|.
  QuicPacketNumber GetLeastUnacked(QuicPathId path_id) const override;

  // Called when a packet has been sent to the peer. If this packet is a
  // retransmission on a different path than the original packet, records the
  // mapping in |transmissions_map_|. Retransmittable frames are transfered from
  // original packet to the sent packet.
  bool OnPacketSent(SerializedPacket* serialized_packet,
                    QuicPathId original_path_id,
                    QuicPacketNumber original_packet_number,
                    QuicTime sent_time,
                    TransmissionType transmission_type,
                    HasRetransmittableData has_retransmittable_data) override;

  // Called when the retransmission timer expires.
  void OnRetransmissionTimeout() override;

  // Returns the earliest time the next packet can be sent. Sets |path_id| to be
  // the path on which the next packet should be sent.
  QuicTime::Delta TimeUntilSend(QuicTime now, QuicPathId* path_id) override;

  // Returns the earliest retransmission time of all paths.
  const QuicTime GetRetransmissionTime() const override;

  // Returns the rtt stats of the default path.
  const RttStats* GetRttStats() const override;

  // Returns the estimated bandwidth on default path calculated by the
  // congestion algorithm.
  QuicBandwidth BandwidthEstimate() const override;

  // Returns the sustained bandwidth recorder on the default path.
  const QuicSustainedBandwidthRecorder* SustainedBandwidthRecorder()
      const override;

  // Returns the size of the current congestion window on default path in number
  // of kDefaultTCPMSS-sized segments.
  QuicPacketCount GetCongestionWindowInTcpMss() const override;

  // Determines the number of packets of length |max_packet_length| which fit in
  // the congestion windows for all paths, and returns the max number of packets
  // across all paths.
  QuicPacketCount EstimateMaxPacketsInFlight(
      QuicByteCount max_packet_length) const override;

  // Returns the size of the current congestion window size on the default path
  // in bytes.
  QuicByteCount GetCongestionWindowInBytes() const override;

  // Returns the size of the slow start congestion window in number of 1460 byte
  // TCP segments on the default path.
  QuicPacketCount GetSlowStartThresholdInTcpMss() const override;

  // Returns debugging information about the state of the congestion
  // controller for all paths.
  std::string GetDebugState() const override;

  // No longer retransmit data for |stream_id| on all paths and any pending
  // retransmissions in pending_retransmissions_.
  void CancelRetransmissionsForStream(QuicStreamId stream_id) override;

  void OnConnectionMigration(QuicPathId path_id,
                             PeerAddressChangeType type) override;

  bool IsHandshakeConfirmed() const override;

  // Sets debug delegate for all active paths.
  void SetDebugDelegate(DebugDelegate* debug_delegate) override;

  QuicPacketNumber GetLargestObserved(QuicPathId path_id) const override;

  QuicPacketNumber GetLargestSentPacket(QuicPathId path_id) const override;

  QuicPacketNumber GetLeastPacketAwaitedByPeer(
      QuicPathId path_id) const override;

  // Sets network change visitor for all active paths.
  void SetNetworkChangeVisitor(NetworkChangeVisitor* visitor) override;

  // Returns true if the default path is in slow start.
  bool InSlowStart() const override;

  // These two methods return the consecutive RTO or TLP count of the default
  // path.
  size_t GetConsecutiveRtoCount() const override;
  size_t GetConsecutiveTlpCount() const override;

  void OnApplicationLimited() override;

 private:
  friend class test::QuicConnectionPeer;
  friend class test::QuicMultipathSentPacketManagerPeer;

  // State of per path sent packet manager.
  // TODO(fayang): Need to add a state that path can receive acks but cannot
  // send data.
  enum PathSentPacketManagerState {
    ACTIVE,   // We both send packets and receiving acks on this path.
    CLOSING,  // We stop sending packets and receiving acks on this path. There
              // are retransmittable frames in the unacked packets map.
  };

  // PathSentPacketManagerInfo contains sent packet manager and its state.
  struct NET_EXPORT_PRIVATE PathSentPacketManagerInfo {
    PathSentPacketManagerInfo();
    PathSentPacketManagerInfo(QuicSentPacketManagerInterface* manager,
                              PathSentPacketManagerState state);
    PathSentPacketManagerInfo(const PathSentPacketManagerInfo& other);

    QuicSentPacketManagerInterface* manager;
    PathSentPacketManagerState state;
  };

  // Returns path sent packet manager if it exists for |path_id|, returns
  // nullptr otherwise.
  QuicSentPacketManagerInterface* MaybeGetSentPacketManagerForPath(
      QuicPathId path_id) const;

  // Returns path sent packet manager if it exists and |path_id| is ACTIVE,
  // returns nullptr otherwise.
  QuicSentPacketManagerInterface* MaybeGetSentPacketManagerForActivePath(
      QuicPathId path_id) const;

  // Returns the path which has the earliest retransmission time.
  QuicPathId DetermineRetransmissionTimeoutPath() const;

  // Close the connection on unrecoverable path errors.
  void OnUnrecoverablePathError(QuicPathId path_id);

  // Current path sent packet managers info, index is path id.
  std::vector<PathSentPacketManagerInfo> path_managers_info_;

  // Does not own this delegate.
  QuicConnectionCloseDelegateInterface* delegate_;

  DISALLOW_COPY_AND_ASSIGN(QuicMultipathSentPacketManager);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_MULTIPATH_SENT_PACKET_MANAGER_H_
