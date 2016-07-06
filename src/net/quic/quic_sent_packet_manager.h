// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_SENT_PACKET_MANAGER_H_
#define NET_QUIC_QUIC_SENT_PACKET_MANAGER_H_

#include <stddef.h>

#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "net/base/linked_hash_map.h"
#include "net/quic/congestion_control/loss_detection_interface.h"
#include "net/quic/congestion_control/rtt_stats.h"
#include "net/quic/congestion_control/send_algorithm_interface.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_sent_packet_manager_interface.h"
#include "net/quic/quic_unacked_packet_map.h"

namespace net {

namespace test {
class QuicConnectionPeer;
class QuicSentPacketManagerPeer;
}  // namespace test

class QuicClock;
class QuicConfig;
struct QuicConnectionStats;

// Class which tracks the set of packets sent on a QUIC connection and contains
// a send algorithm to decide when to send new packets.  It keeps track of any
// retransmittable data associated with each packet. If a packet is
// retransmitted, it will keep track of each version of a packet so that if a
// previous transmission is acked, the data will not be retransmitted.
class NET_EXPORT_PRIVATE QuicSentPacketManager
    : public QuicSentPacketManagerInterface {
 public:
  // A delegate interface which manages pending retransmissions.
  class MultipathDelegateInterface {
   public:
    virtual ~MultipathDelegateInterface() {}

    // Called when unencrypted |packet_number| is requested to be neutered.
    virtual void OnUnencryptedPacketsNeutered(
        QuicPathId path_id,
        QuicPacketNumber packet_number) = 0;
    // Called when |packet_number| is requested to be retransmitted.
    virtual void OnRetransmissionMarked(QuicPathId path_id,
                                        QuicPacketNumber packet_number,
                                        TransmissionType transmission_type) = 0;
    // Called when |packet_number| is marked as not retransmittable.
    virtual void OnPacketMarkedNotRetransmittable(
        QuicPathId path_id,
        QuicPacketNumber packet_number,
        QuicTime::Delta delta_largest_observed) = 0;
    // Called when any transmission of |packet_number| is handled.
    virtual void OnPacketMarkedHandled(
        QuicPathId path_id,
        QuicPacketNumber packet_number,
        QuicTime::Delta delta_largest_observed) = 0;
  };

  QuicSentPacketManager(Perspective perspective,
                        QuicPathId path_id,
                        const QuicClock* clock,
                        QuicConnectionStats* stats,
                        CongestionControlType congestion_control_type,
                        LossDetectionType loss_type,
                        MultipathDelegateInterface* delegate);
  ~QuicSentPacketManager() override;

  // Start implementation of QuicSentPacketManagerInterface.
  void SetFromConfig(const QuicConfig& config) override;

  // Pass the CachedNetworkParameters to the send algorithm.
  void ResumeConnectionState(
      const CachedNetworkParameters& cached_network_params,
      bool max_bandwidth_resumption) override;

  void SetNumOpenStreams(size_t num_streams) override;

  void SetMaxPacingRate(QuicBandwidth max_pacing_rate) override;

  void SetHandshakeConfirmed() override;

  // Processes the incoming ack.
  void OnIncomingAck(const QuicAckFrame& ack_frame,
                     QuicTime ack_receive_time) override;

  // Returns true if packet |packet_number| is unacked.
  bool IsUnacked(QuicPathId, QuicPacketNumber packet_number) const override;

  // Requests retransmission of all unacked packets of |retransmission_type|.
  // The behavior of this method depends on the value of |retransmission_type|:
  // ALL_UNACKED_RETRANSMISSION - All unacked packets will be retransmitted.
  // This can happen, for example, after a version negotiation packet has been
  // received and all packets needs to be retransmitted with the new version.
  // ALL_INITIAL_RETRANSMISSION - Only initially encrypted packets will be
  // retransmitted. This can happen, for example, when a CHLO has been rejected
  // and the previously encrypted data needs to be encrypted with a new key.
  void RetransmitUnackedPackets(TransmissionType retransmission_type) override;

  // Retransmits the oldest pending packet there is still a tail loss probe
  // pending.  Invoked after OnRetransmissionTimeout.
  bool MaybeRetransmitTailLossProbe() override;

  // Removes the retransmittable frames from all unencrypted packets to ensure
  // they don't get retransmitted.
  void NeuterUnencryptedPackets() override;

  // Returns true if the unacked packet |packet_number| has retransmittable
  // frames.  This will only return false if the packet has been acked, if a
  // previous transmission of this packet was ACK'd, or if this packet has been
  // retransmitted as with different packet number.
  bool HasRetransmittableFrames(QuicPathId,
                                QuicPacketNumber packet_number) const override;

  // Returns true if there are pending retransmissions.
  // Not const because retransmissions may be cancelled before returning.
  bool HasPendingRetransmissions() const override;

  // Retrieves the next pending retransmission.  You must ensure that
  // there are pending retransmissions prior to calling this function.
  PendingRetransmission NextPendingRetransmission() override;

  bool HasUnackedPackets() const override;

  // Returns the smallest packet number of a serialized packet which has not
  // been acked by the peer.
  QuicPacketNumber GetLeastUnacked(QuicPathId) const override;

  // Called when we have sent bytes to the peer.  This informs the manager both
  // the number of bytes sent and if they were retransmitted.  Returns true if
  // the sender should reset the retransmission timer.
  bool OnPacketSent(SerializedPacket* serialized_packet,
                    QuicPathId /*original_path_id*/,
                    QuicPacketNumber original_packet_number,
                    QuicTime sent_time,
                    TransmissionType transmission_type,
                    HasRetransmittableData has_retransmittable_data) override;

  // Called when the retransmission timer expires.
  void OnRetransmissionTimeout() override;

  // Calculate the time until we can send the next packet to the wire.
  // Note 1: When kUnknownWaitTime is returned, there is no need to poll
  // TimeUntilSend again until we receive an OnIncomingAckFrame event.
  // Note 2: Send algorithms may or may not use |retransmit| in their
  // calculations.
  QuicTime::Delta TimeUntilSend(QuicTime now,
                                HasRetransmittableData retransmittable,
                                QuicPathId* path_id) override;

  // Returns the current delay for the retransmission timer, which may send
  // either a tail loss probe or do a full RTO.  Returns QuicTime::Zero() if
  // there are no retransmittable packets.
  const QuicTime GetRetransmissionTime() const override;

  const RttStats* GetRttStats() const override;

  // Returns the estimated bandwidth calculated by the congestion algorithm.
  QuicBandwidth BandwidthEstimate() const override;

  const QuicSustainedBandwidthRecorder& SustainedBandwidthRecorder()
      const override;

  // Returns the size of the current congestion window in number of
  // kDefaultTCPMSS-sized segments. Note, this is not the *available* window.
  // Some send algorithms may not use a congestion window and will return 0.
  QuicPacketCount GetCongestionWindowInTcpMss() const override;

  // Returns the number of packets of length |max_packet_length| which fit in
  // the current congestion window. More packets may end up in flight if the
  // congestion window has been recently reduced, of if non-full packets are
  // sent.
  QuicPacketCount EstimateMaxPacketsInFlight(
      QuicByteCount max_packet_length) const override;

  // Returns the size of the current congestion window size in bytes.
  QuicByteCount GetCongestionWindowInBytes() const override;

  // Returns the size of the slow start congestion window in nume of 1460 byte
  // TCP segments, aka ssthresh.  Some send algorithms do not define a slow
  // start threshold and will return 0.
  QuicPacketCount GetSlowStartThresholdInTcpMss() const override;

  // No longer retransmit data for |stream_id|.
  void CancelRetransmissionsForStream(QuicStreamId stream_id) override;

  // Called when peer address changes and the connection migrates.
  void OnConnectionMigration(QuicPathId, PeerAddressChangeType type) override;

  bool IsHandshakeConfirmed() const override;

  void SetDebugDelegate(DebugDelegate* debug_delegate) override;

  QuicPacketNumber GetLargestObserved(QuicPathId) const override;

  QuicPacketNumber GetLargestSentPacket(QuicPathId) const override;

  QuicPacketNumber GetLeastPacketAwaitedByPeer(QuicPathId) const override;

  void SetNetworkChangeVisitor(NetworkChangeVisitor* visitor) override;

  bool InSlowStart() const override;

  size_t GetConsecutiveRtoCount() const override;

  size_t GetConsecutiveTlpCount() const override;

 private:
  friend class test::QuicConnectionPeer;
  friend class test::QuicSentPacketManagerPeer;

  // The retransmission timer is a single timer which switches modes depending
  // upon connection state.
  enum RetransmissionTimeoutMode {
    // A conventional TCP style RTO.
    RTO_MODE,
    // A tail loss probe.  By default, QUIC sends up to two before RTOing.
    TLP_MODE,
    // Retransmission of handshake packets prior to handshake completion.
    HANDSHAKE_MODE,
    // Re-invoke the loss detection when a packet is not acked before the
    // loss detection algorithm expects.
    LOSS_MODE,
  };

  typedef linked_hash_map<QuicPacketNumber, TransmissionType>
      PendingRetransmissionMap;

  // Updates the least_packet_awaited_by_peer.
  void UpdatePacketInformationReceivedByPeer(const QuicAckFrame& ack_frame);

  // Process the incoming ack looking for newly ack'd data packets.
  void HandleAckForSentPackets(const QuicAckFrame& ack_frame);

  // Returns the current retransmission mode.
  RetransmissionTimeoutMode GetRetransmissionMode() const;

  // Retransmits all crypto stream packets.
  void RetransmitCryptoPackets();

  // Retransmits two packets for an RTO and removes any non-retransmittable
  // packets from flight.
  void RetransmitRtoPackets();

  // Returns the timer for retransmitting crypto handshake packets.
  const QuicTime::Delta GetCryptoRetransmissionDelay() const;

  // Returns the timer for a new tail loss probe.
  const QuicTime::Delta GetTailLossProbeDelay() const;

  // Returns the retransmission timeout, after which a full RTO occurs.
  const QuicTime::Delta GetRetransmissionDelay() const;

  // Returns the newest transmission associated with a packet.
  QuicPacketNumber GetNewestRetransmission(
      QuicPacketNumber packet_number,
      const TransmissionInfo& transmission_info) const;

  // Update the RTT if the ack is for the largest acked packet number.
  // Returns true if the rtt was updated.
  bool MaybeUpdateRTT(const QuicAckFrame& ack_frame, QuicTime ack_receive_time);

  // Invokes the loss detection algorithm and loses and retransmits packets if
  // necessary.
  void InvokeLossDetection(QuicTime time);

  // Invokes OnCongestionEvent if |rtt_updated| is true, there are pending acks,
  // or pending losses.  Clears pending acks and pending losses afterwards.
  // |bytes_in_flight| is the number of bytes in flight before the losses or
  // acks.
  void MaybeInvokeCongestionEvent(bool rtt_updated,
                                  QuicByteCount bytes_in_flight);

  // Called when frames of |packet_number| has been received but the packet
  // itself has not been received by the peer. Currently, this method is not
  // used.
  // TODO(fayang): Update the comment when multipath sent packet manager is
  // landed.
  // The packet needs no longer to be retransmitted, but the packet remains
  // pending if it is and the congestion control does not consider the packet
  // acked.
  void MarkPacketNotRetransmittable(QuicPacketNumber packet_number,
                                    QuicTime::Delta ack_delay_time);

  // Removes the retransmittability and in flight properties from the packet at
  // |info| due to receipt by the peer.
  void MarkPacketHandled(QuicPacketNumber packet_number,
                         TransmissionInfo* info,
                         QuicTime::Delta ack_delay_time);

  // Request that |packet_number| be retransmitted after the other pending
  // retransmissions.  Does not add it to the retransmissions if it's already
  // a pending retransmission.
  void MarkForRetransmission(QuicPacketNumber packet_number,
                             TransmissionType transmission_type);

  // Notify observers that packet with TransmissionInfo |info| is a spurious
  // retransmission. It is caller's responsibility to guarantee the packet with
  // TransmissionInfo |info| is a spurious retransmission before calling this
  // function.
  void RecordOneSpuriousRetransmission(const TransmissionInfo& info);

  // Notify observers about spurious retransmits of packet with TransmissionInfo
  // |info|.
  void RecordSpuriousRetransmissions(const TransmissionInfo& info,
                                     QuicPacketNumber acked_packet_number);

  // Returns mutable TransmissionInfo associated with |packet_number|, which
  // must be unacked.
  TransmissionInfo* GetMutableTransmissionInfo(QuicPacketNumber packet_number);

  // Remove any packets no longer needed for retransmission, congestion, or
  // RTT measurement purposes.
  void RemoveObsoletePackets();

  // Enables pacing if it has not already been enabled.
  void EnablePacing();

  // Newly serialized retransmittable packets are added to this map, which
  // contains owning pointers to any contained frames.  If a packet is
  // retransmitted, this map will contain entries for both the old and the new
  // packet. The old packet's retransmittable frames entry will be nullptr,
  // while the new packet's entry will contain the frames to retransmit.
  // If the old packet is acked before the new packet, then the old entry will
  // be removed from the map and the new entry's retransmittable frames will be
  // set to nullptr.
  QuicUnackedPacketMap unacked_packets_;

  // Pending retransmissions which have not been packetized and sent yet.
  PendingRetransmissionMap pending_retransmissions_;

  // Tracks if the connection was created by the server or the client.
  Perspective perspective_;

  QuicPathId path_id_;

  const QuicClock* clock_;
  QuicConnectionStats* stats_;

  // Pending retransmissions are managed by delegate_ if it is not null.
  MultipathDelegateInterface* delegate_;  // Not owned.

  DebugDelegate* debug_delegate_;
  NetworkChangeVisitor* network_change_visitor_;
  const QuicPacketCount initial_congestion_window_;
  RttStats rtt_stats_;
  std::unique_ptr<SendAlgorithmInterface> send_algorithm_;
  std::unique_ptr<LossDetectionInterface> loss_algorithm_;
  bool n_connection_simulation_;

  // Receiver side buffer in bytes.
  QuicByteCount receive_buffer_bytes_;

  // Least packet number which the peer is still waiting for.
  QuicPacketNumber least_packet_awaited_by_peer_;

  // Tracks the first RTO packet.  If any packet before that packet gets acked,
  // it indicates the RTO was spurious and should be reversed(F-RTO).
  QuicPacketNumber first_rto_transmission_;
  // Number of times the RTO timer has fired in a row without receiving an ack.
  size_t consecutive_rto_count_;
  // Number of times the tail loss probe has been sent.
  size_t consecutive_tlp_count_;
  // Number of times the crypto handshake has been retransmitted.
  size_t consecutive_crypto_retransmission_count_;
  // Number of pending transmissions of TLP, RTO, or crypto packets.
  size_t pending_timer_transmission_count_;
  // Maximum number of tail loss probes to send before firing an RTO.
  size_t max_tail_loss_probes_;
  // If true, send the TLP at 0.5 RTT.
  bool enable_half_rtt_tail_loss_probe_;
  bool using_pacing_;
  // If true, use the new RTO with loss based CWND reduction instead of the send
  // algorithms's OnRetransmissionTimeout to reduce the congestion window.
  bool use_new_rto_;
  // If true, cancel pending retransmissions if they're larger than
  // largest_newly_acked.
  bool undo_pending_retransmits_;

  // Vectors packets acked and lost as a result of the last congestion event.
  SendAlgorithmInterface::CongestionVector packets_acked_;
  SendAlgorithmInterface::CongestionVector packets_lost_;
  // Largest newly acknowledged packet.
  QuicPacketNumber largest_newly_acked_;
  // Largest packet in bytes ever acknowledged.
  QuicPacketLength largest_mtu_acked_;

  // Set to true after the crypto handshake has successfully completed. After
  // this is true we no longer use HANDSHAKE_MODE, and further frames sent on
  // the crypto stream (i.e. SCUP messages) are treated like normal
  // retransmittable frames.
  bool handshake_confirmed_;

  // Records bandwidth from server to client in normal operation, over periods
  // of time with no loss events.
  QuicSustainedBandwidthRecorder sustained_bandwidth_recorder_;

  DISALLOW_COPY_AND_ASSIGN(QuicSentPacketManager);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_SENT_PACKET_MANAGER_H_
