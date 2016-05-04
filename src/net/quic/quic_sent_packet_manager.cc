// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_sent_packet_manager.h"

#include <algorithm>

#include "base/logging.h"
#include "base/stl_util.h"
#include "net/quic/congestion_control/pacing_sender.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/proto/cached_network_parameters.pb.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_connection_stats.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils_chromium.h"

using std::max;
using std::min;
using std::pair;

namespace net {

// The length of the recent min rtt window in seconds. Windowing is disabled for
// values less than or equal to 0.
int32_t FLAGS_quic_recent_min_rtt_window_s = 60;

namespace {
static const int64_t kDefaultRetransmissionTimeMs = 500;
// TCP RFC calls for 1 second RTO however Linux differs from this default and
// define the minimum RTO to 200ms, we will use the same until we have data to
// support a higher or lower value.
static const int64_t kMinRetransmissionTimeMs = 200;
static const int64_t kMaxRetransmissionTimeMs = 60000;
// Maximum number of exponential backoffs used for RTO timeouts.
static const size_t kMaxRetransmissions = 10;
// Maximum number of packets retransmitted upon an RTO.
static const size_t kMaxRetransmissionsOnTimeout = 2;
// Minimum number of consecutive RTOs before path is considered to be degrading.
const size_t kMinTimeoutsBeforePathDegrading = 2;

// Ensure the handshake timer isnt't faster than 10ms.
// This limits the tenth retransmitted packet to 10s after the initial CHLO.
static const int64_t kMinHandshakeTimeoutMs = 10;

// Sends up to two tail loss probes before firing an RTO,
// per draft RFC draft-dukkipati-tcpm-tcp-loss-probe.
static const size_t kDefaultMaxTailLossProbes = 2;

// Number of unpaced packets to send after quiescence.
static const size_t kInitialUnpacedBurst = 10;

bool HasCryptoHandshake(const TransmissionInfo& transmission_info) {
  DCHECK(!transmission_info.has_crypto_handshake ||
         !transmission_info.retransmittable_frames.empty());
  return transmission_info.has_crypto_handshake;
}

}  // namespace

#define ENDPOINT \
  (perspective_ == Perspective::IS_SERVER ? "Server: " : "Client: ")

QuicSentPacketManager::QuicSentPacketManager(
    Perspective perspective,
    QuicPathId path_id,
    const QuicClock* clock,
    QuicConnectionStats* stats,
    CongestionControlType congestion_control_type,
    LossDetectionType loss_type,
    MultipathDelegateInterface* delegate)
    : unacked_packets_(),
      perspective_(perspective),
      path_id_(path_id),
      clock_(clock),
      stats_(stats),
      delegate_(delegate),
      debug_delegate_(nullptr),
      network_change_visitor_(nullptr),
      initial_congestion_window_(kInitialCongestionWindow),
      send_algorithm_(
          SendAlgorithmInterface::Create(clock,
                                         &rtt_stats_,
                                         congestion_control_type,
                                         stats,
                                         initial_congestion_window_)),
      loss_algorithm_(LossDetectionInterface::Create(loss_type)),
      n_connection_simulation_(false),
      receive_buffer_bytes_(kDefaultSocketReceiveBuffer),
      least_packet_awaited_by_peer_(1),
      first_rto_transmission_(0),
      consecutive_rto_count_(0),
      consecutive_tlp_count_(0),
      consecutive_crypto_retransmission_count_(0),
      pending_timer_transmission_count_(0),
      max_tail_loss_probes_(kDefaultMaxTailLossProbes),
      enable_half_rtt_tail_loss_probe_(false),
      using_pacing_(false),
      use_new_rto_(false),
      handshake_confirmed_(false) {}

QuicSentPacketManager::~QuicSentPacketManager() {}

void QuicSentPacketManager::SetFromConfig(const QuicConfig& config) {
  if (config.HasReceivedInitialRoundTripTimeUs() &&
      config.ReceivedInitialRoundTripTimeUs() > 0) {
    rtt_stats_.set_initial_rtt_us(
        max(kMinInitialRoundTripTimeUs,
            min(kMaxInitialRoundTripTimeUs,
                config.ReceivedInitialRoundTripTimeUs())));
  } else if (config.HasInitialRoundTripTimeUsToSend() &&
             config.GetInitialRoundTripTimeUsToSend() > 0) {
    rtt_stats_.set_initial_rtt_us(
        max(kMinInitialRoundTripTimeUs,
            min(kMaxInitialRoundTripTimeUs,
                config.GetInitialRoundTripTimeUsToSend())));
  }
  // Initial RTT may have changed.
  if (network_change_visitor_ != nullptr) {
    network_change_visitor_->OnRttChange();
  }
  // TODO(ianswett): BBR is currently a server only feature.
  if (FLAGS_quic_allow_bbr && config.HasReceivedConnectionOptions() &&
      ContainsQuicTag(config.ReceivedConnectionOptions(), kTBBR)) {
    if (FLAGS_quic_recent_min_rtt_window_s > 0) {
      rtt_stats_.set_recent_min_rtt_window(
          QuicTime::Delta::FromSeconds(FLAGS_quic_recent_min_rtt_window_s));
    }
    send_algorithm_.reset(SendAlgorithmInterface::Create(
        clock_, &rtt_stats_, kBBR, stats_, initial_congestion_window_));
  }
  if (config.HasReceivedConnectionOptions() &&
      ContainsQuicTag(config.ReceivedConnectionOptions(), kRENO)) {
    if (ContainsQuicTag(config.ReceivedConnectionOptions(), kBYTE)) {
      send_algorithm_.reset(SendAlgorithmInterface::Create(
          clock_, &rtt_stats_, kRenoBytes, stats_, initial_congestion_window_));
    } else {
      send_algorithm_.reset(SendAlgorithmInterface::Create(
          clock_, &rtt_stats_, kReno, stats_, initial_congestion_window_));
    }
  } else if (config.HasReceivedConnectionOptions() &&
             ContainsQuicTag(config.ReceivedConnectionOptions(), kBYTE)) {
    send_algorithm_.reset(SendAlgorithmInterface::Create(
        clock_, &rtt_stats_, kCubicBytes, stats_, initial_congestion_window_));
  }
  if (!FLAGS_quic_disable_pacing) {
    EnablePacing();
  }

  if (config.HasClientSentConnectionOption(k1CON, perspective_)) {
    send_algorithm_->SetNumEmulatedConnections(1);
  }
  if (config.HasClientSentConnectionOption(kNCON, perspective_)) {
    n_connection_simulation_ = true;
  }
  if (config.HasClientSentConnectionOption(kNTLP, perspective_)) {
    max_tail_loss_probes_ = 0;
  }
  if (config.HasClientSentConnectionOption(kTLPR, perspective_)) {
    enable_half_rtt_tail_loss_probe_ = true;
  }
  if (config.HasClientSentConnectionOption(kNRTO, perspective_)) {
    use_new_rto_ = true;
  }
  if (config.HasReceivedConnectionOptions() &&
      ContainsQuicTag(config.ReceivedConnectionOptions(), kTIME)) {
    loss_algorithm_.reset(LossDetectionInterface::Create(kTime));
  }
  if (config.HasReceivedSocketReceiveBuffer()) {
    receive_buffer_bytes_ =
        max(kMinSocketReceiveBuffer,
            static_cast<QuicByteCount>(config.ReceivedSocketReceiveBuffer()));
    QuicByteCount max_cwnd_bytes = static_cast<QuicByteCount>(
        receive_buffer_bytes_ * kConservativeReceiveBufferFraction);
    send_algorithm_->SetMaxCongestionWindow(max_cwnd_bytes);
  }
  send_algorithm_->SetFromConfig(config, perspective_);

  if (network_change_visitor_ != nullptr) {
    network_change_visitor_->OnCongestionWindowChange();
  }
}

void QuicSentPacketManager::ResumeConnectionState(
    const CachedNetworkParameters& cached_network_params,
    bool max_bandwidth_resumption) {
  if (cached_network_params.has_min_rtt_ms()) {
    uint32_t initial_rtt_us =
        kNumMicrosPerMilli * cached_network_params.min_rtt_ms();
    rtt_stats_.set_initial_rtt_us(
        max(kMinInitialRoundTripTimeUs,
            min(kMaxInitialRoundTripTimeUs, initial_rtt_us)));
  }
  send_algorithm_->ResumeConnectionState(cached_network_params,
                                         max_bandwidth_resumption);
}

void QuicSentPacketManager::SetNumOpenStreams(size_t num_streams) {
  if (n_connection_simulation_) {
    // Ensure the number of connections is between 1 and 5.
    send_algorithm_->SetNumEmulatedConnections(
        min<size_t>(5, max<size_t>(1, num_streams)));
  }
}

void QuicSentPacketManager::OnIncomingAck(const QuicAckFrame& ack_frame,
                                          QuicTime ack_receive_time) {
  QuicByteCount bytes_in_flight = unacked_packets_.bytes_in_flight();

  UpdatePacketInformationReceivedByPeer(ack_frame);
  bool rtt_updated = MaybeUpdateRTT(ack_frame, ack_receive_time);
  DCHECK_GE(ack_frame.largest_observed, unacked_packets_.largest_observed());
  unacked_packets_.IncreaseLargestObserved(ack_frame.largest_observed);

  HandleAckForSentPackets(ack_frame);
  InvokeLossDetection(ack_receive_time);
  // Ignore losses in RTO mode.
  if (consecutive_rto_count_ > 0 && !use_new_rto_) {
    packets_lost_.clear();
  }
  MaybeInvokeCongestionEvent(rtt_updated, bytes_in_flight);
  unacked_packets_.RemoveObsoletePackets();

  sustained_bandwidth_recorder_.RecordEstimate(
      send_algorithm_->InRecovery(), send_algorithm_->InSlowStart(),
      send_algorithm_->BandwidthEstimate(), ack_receive_time, clock_->WallNow(),
      rtt_stats_.smoothed_rtt());

  // Anytime we are making forward progress and have a new RTT estimate, reset
  // the backoff counters.
  if (rtt_updated) {
    if (consecutive_rto_count_ > 0) {
      // If the ack acknowledges data sent prior to the RTO,
      // the RTO was spurious.
      if (ack_frame.largest_observed < first_rto_transmission_) {
        // Replace SRTT with latest_rtt and increase the variance to prevent
        // a spurious RTO from happening again.
        rtt_stats_.ExpireSmoothedMetrics();
      } else {
        if (!use_new_rto_) {
          send_algorithm_->OnRetransmissionTimeout(true);
        }
      }
    }
    // Reset all retransmit counters any time a new packet is acked.
    consecutive_rto_count_ = 0;
    consecutive_tlp_count_ = 0;
    consecutive_crypto_retransmission_count_ = 0;
  }

  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnIncomingAck(ack_frame, ack_receive_time,
                                   unacked_packets_.largest_observed(),
                                   rtt_updated, GetLeastUnacked());
  }
}

void QuicSentPacketManager::UpdatePacketInformationReceivedByPeer(
    const QuicAckFrame& ack_frame) {
  if (ack_frame.missing_packets.Empty()) {
    least_packet_awaited_by_peer_ = ack_frame.largest_observed + 1;
  } else {
    least_packet_awaited_by_peer_ = ack_frame.missing_packets.Min();
  }
}

void QuicSentPacketManager::MaybeInvokeCongestionEvent(
    bool rtt_updated,
    QuicByteCount bytes_in_flight) {
  if (!rtt_updated && packets_acked_.empty() && packets_lost_.empty()) {
    return;
  }
  send_algorithm_->OnCongestionEvent(rtt_updated, bytes_in_flight,
                                     packets_acked_, packets_lost_);
  packets_acked_.clear();
  packets_lost_.clear();
  if (network_change_visitor_ != nullptr) {
    network_change_visitor_->OnCongestionWindowChange();
  }
}

void QuicSentPacketManager::HandleAckForSentPackets(
    const QuicAckFrame& ack_frame) {
  // Go through the packets we have not received an ack for and see if this
  // incoming_ack shows they've been seen by the peer.
  QuicTime::Delta ack_delay_time = ack_frame.ack_delay_time;
  QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
  for (QuicUnackedPacketMap::iterator it = unacked_packets_.begin();
       it != unacked_packets_.end(); ++it, ++packet_number) {
    if (packet_number > ack_frame.largest_observed) {
      // These packets are still in flight.
      break;
    }

    if (ack_frame.missing_packets.Contains(packet_number)) {
      // Don't continue to increase the nack count for packets not in flight.
      if (FLAGS_quic_simplify_loss_detection || !it->in_flight) {
        continue;
      }
      // Consider it multiple nacks when there is a gap between the missing
      // packet and the largest observed, since the purpose of a nack
      // threshold is to tolerate re-ordering.  This handles both StretchAcks
      // and Forward Acks.
      // The nack count only increases when the largest observed increases.
      QuicPacketCount min_nacks = ack_frame.largest_observed - packet_number;
      // Truncated acks can nack the largest observed, so use a min of 1.
      if (min_nacks == 0) {
        min_nacks = 1;
      }
      unacked_packets_.NackPacket(packet_number, min_nacks);
      continue;
    }
    // Packet was acked, so remove it from our unacked packet list.
    DVLOG(1) << ENDPOINT << "Got an ack for packet " << packet_number;
    // If data is associated with the most recent transmission of this
    // packet, then inform the caller.
    if (it->in_flight) {
      packets_acked_.push_back(std::make_pair(packet_number, it->bytes_sent));
    }
    MarkPacketHandled(packet_number, &(*it), ack_delay_time);
  }
}

bool QuicSentPacketManager::HasRetransmittableFrames(
    QuicPacketNumber packet_number) const {
  return unacked_packets_.HasRetransmittableFrames(packet_number);
}

void QuicSentPacketManager::RetransmitUnackedPackets(
    TransmissionType retransmission_type) {
  DCHECK(retransmission_type == ALL_UNACKED_RETRANSMISSION ||
         retransmission_type == ALL_INITIAL_RETRANSMISSION);
  QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
  for (QuicUnackedPacketMap::const_iterator it = unacked_packets_.begin();
       it != unacked_packets_.end(); ++it, ++packet_number) {
    if (!it->retransmittable_frames.empty() &&
        (retransmission_type == ALL_UNACKED_RETRANSMISSION ||
         it->encryption_level == ENCRYPTION_INITIAL)) {
      MarkForRetransmission(packet_number, retransmission_type);
    }
  }
}

void QuicSentPacketManager::NeuterUnencryptedPackets() {
  QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
  for (QuicUnackedPacketMap::const_iterator it = unacked_packets_.begin();
       it != unacked_packets_.end(); ++it, ++packet_number) {
    if (!it->retransmittable_frames.empty() &&
        it->encryption_level == ENCRYPTION_NONE) {
      // Once you're forward secure, no unencrypted packets will be sent, crypto
      // or otherwise. Unencrypted packets are neutered and abandoned, to ensure
      // they are not retransmitted or considered lost from a congestion control
      // perspective.
      if (delegate_ != nullptr) {
        delegate_->OnUnencryptedPacketsNeutered(path_id_, packet_number);
      } else {
        pending_retransmissions_.erase(packet_number);
      }
      unacked_packets_.RemoveFromInFlight(packet_number);
      unacked_packets_.RemoveRetransmittability(packet_number);
    }
  }
}

void QuicSentPacketManager::MarkForRetransmission(
    QuicPacketNumber packet_number,
    TransmissionType transmission_type) {
  const TransmissionInfo& transmission_info =
      unacked_packets_.GetTransmissionInfo(packet_number);
  QUIC_BUG_IF(transmission_info.retransmittable_frames.empty());
  // Both TLP and the new RTO leave the packets in flight and let the loss
  // detection decide if packets are lost.
  if (transmission_type != TLP_RETRANSMISSION &&
      transmission_type != RTO_RETRANSMISSION) {
    unacked_packets_.RemoveFromInFlight(packet_number);
  }
  if (delegate_ != nullptr) {
    delegate_->OnRetransmissionMarked(path_id_, packet_number,
                                      transmission_type);
  } else {
    // TODO(ianswett): Currently the RTO can fire while there are pending NACK
    // retransmissions for the same data, which is not ideal.
    if (ContainsKey(pending_retransmissions_, packet_number)) {
      return;
    }

    pending_retransmissions_[packet_number] = transmission_type;
  }
}

void QuicSentPacketManager::RecordOneSpuriousRetransmission(
    const TransmissionInfo& info) {
  stats_->bytes_spuriously_retransmitted += info.bytes_sent;
  ++stats_->packets_spuriously_retransmitted;
  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnSpuriousPacketRetransmission(info.transmission_type,
                                                    info.bytes_sent);
  }
}

void QuicSentPacketManager::RecordSpuriousRetransmissions(
    const TransmissionInfo& info,
    QuicPacketNumber acked_packet_number) {
  QuicPacketNumber retransmission = info.retransmission;
  while (retransmission != 0) {
    const TransmissionInfo& retransmit_info =
        unacked_packets_.GetTransmissionInfo(retransmission);
    retransmission = retransmit_info.retransmission;
    RecordOneSpuriousRetransmission(retransmit_info);
  }
}

bool QuicSentPacketManager::HasPendingRetransmissions() const {
  return !pending_retransmissions_.empty();
}

PendingRetransmission QuicSentPacketManager::NextPendingRetransmission() {
  QUIC_BUG_IF(pending_retransmissions_.empty())
      << "Unexpected call to PendingRetransmissions() with empty pending "
      << "retransmission list. Corrupted memory usage imminent.";
  QuicPacketNumber packet_number = pending_retransmissions_.begin()->first;
  TransmissionType transmission_type = pending_retransmissions_.begin()->second;
  if (unacked_packets_.HasPendingCryptoPackets()) {
    // Ensure crypto packets are retransmitted before other packets.
    for (const auto& pair : pending_retransmissions_) {
      if (HasCryptoHandshake(
              unacked_packets_.GetTransmissionInfo(pair.first))) {
        packet_number = pair.first;
        transmission_type = pair.second;
        break;
      }
    }
  }
  DCHECK(unacked_packets_.IsUnacked(packet_number)) << packet_number;
  const TransmissionInfo& transmission_info =
      unacked_packets_.GetTransmissionInfo(packet_number);
  DCHECK(!transmission_info.retransmittable_frames.empty());

  return PendingRetransmission(path_id_, packet_number, transmission_type,
                               transmission_info.retransmittable_frames,
                               transmission_info.has_crypto_handshake,
                               transmission_info.num_padding_bytes,
                               transmission_info.encryption_level,
                               transmission_info.packet_number_length);
}

QuicPacketNumber QuicSentPacketManager::GetNewestRetransmission(
    QuicPacketNumber packet_number,
    const TransmissionInfo& transmission_info) const {
  QuicPacketNumber retransmission = transmission_info.retransmission;
  while (retransmission != 0) {
    packet_number = retransmission;
    retransmission =
        unacked_packets_.GetTransmissionInfo(retransmission).retransmission;
  }
  return packet_number;
}

void QuicSentPacketManager::MarkPacketNotRetransmittable(
    QuicPacketNumber packet_number,
    QuicTime::Delta ack_delay_time) {
  if (!unacked_packets_.IsUnacked(packet_number)) {
    return;
  }

  const TransmissionInfo& transmission_info =
      unacked_packets_.GetTransmissionInfo(packet_number);
  QuicPacketNumber newest_transmission =
      GetNewestRetransmission(packet_number, transmission_info);
  // We do not need to retransmit this packet anymore.
  if (delegate_ != nullptr) {
    delegate_->OnPacketMarkedNotRetransmittable(path_id_, newest_transmission,
                                                ack_delay_time);
  } else {
    pending_retransmissions_.erase(newest_transmission);
  }

  unacked_packets_.NotifyAndClearListeners(newest_transmission, ack_delay_time);
  unacked_packets_.RemoveRetransmittability(packet_number);
}

void QuicSentPacketManager::MarkPacketHandled(QuicPacketNumber packet_number,
                                              TransmissionInfo* info,
                                              QuicTime::Delta ack_delay_time) {
  QuicPacketNumber newest_transmission =
      GetNewestRetransmission(packet_number, *info);
  // Remove the most recent packet, if it is pending retransmission.
  if (delegate_ != nullptr) {
    delegate_->OnPacketMarkedHandled(path_id_, newest_transmission,
                                     ack_delay_time);
  } else {
    pending_retransmissions_.erase(newest_transmission);
  }

  // The AckListener needs to be notified about the most recent
  // transmission, since that's the one only one it tracks.
  if (newest_transmission == packet_number) {
    unacked_packets_.NotifyAndClearListeners(&info->ack_listeners,
                                             ack_delay_time);
  } else {
    unacked_packets_.NotifyAndClearListeners(newest_transmission,
                                             ack_delay_time);
    RecordSpuriousRetransmissions(*info, packet_number);
    // Remove the most recent packet from flight if it's a crypto handshake
    // packet, since they won't be acked now that one has been processed.
    // Other crypto handshake packets won't be in flight, only the newest
    // transmission of a crypto packet is in flight at once.
    // TODO(ianswett): Instead of handling all crypto packets special,
    // only handle nullptr encrypted packets in a special way.
    const TransmissionInfo& newest_transmission_info =
        unacked_packets_.GetTransmissionInfo(newest_transmission);
    if (HasCryptoHandshake(newest_transmission_info)) {
      unacked_packets_.RemoveFromInFlight(newest_transmission);
    }
  }

  unacked_packets_.RemoveFromInFlight(info);
  unacked_packets_.RemoveRetransmittability(info);
}

bool QuicSentPacketManager::IsUnacked(QuicPacketNumber packet_number) const {
  return unacked_packets_.IsUnacked(packet_number);
}

bool QuicSentPacketManager::HasUnackedPackets() const {
  return unacked_packets_.HasUnackedPackets();
}

QuicPacketNumber QuicSentPacketManager::GetLeastUnacked() const {
  return unacked_packets_.GetLeastUnacked();
}

bool QuicSentPacketManager::OnPacketSent(
    SerializedPacket* serialized_packet,
    QuicPacketNumber original_packet_number,
    QuicTime sent_time,
    TransmissionType transmission_type,
    HasRetransmittableData has_retransmittable_data) {
  QuicPacketNumber packet_number = serialized_packet->packet_number;
  DCHECK_LT(0u, packet_number);
  DCHECK(!unacked_packets_.IsUnacked(packet_number));
  QUIC_BUG_IF(serialized_packet->encrypted_length == 0)
      << "Cannot send empty packets.";

  if (delegate_ == nullptr && original_packet_number != 0) {
    if (!pending_retransmissions_.erase(original_packet_number)) {
      QUIC_BUG << "Expected packet number to be in "
               << "pending_retransmissions_.  packet_number: "
               << original_packet_number;
    }
  }

  if (pending_timer_transmission_count_ > 0) {
    --pending_timer_transmission_count_;
  }

  // TODO(ianswett): Remove sent_time, because it's unused.
  const bool in_flight = send_algorithm_->OnPacketSent(
      sent_time, unacked_packets_.bytes_in_flight(), packet_number,
      serialized_packet->encrypted_length, has_retransmittable_data);

  unacked_packets_.AddSentPacket(serialized_packet, original_packet_number,
                                 transmission_type, sent_time, in_flight);
  // Reset the retransmission timer anytime a pending packet is sent.
  return in_flight;
}

void QuicSentPacketManager::OnRetransmissionTimeout() {
  DCHECK(unacked_packets_.HasInFlightPackets());
  DCHECK_EQ(0u, pending_timer_transmission_count_);
  // Handshake retransmission, timer based loss detection, TLP, and RTO are
  // implemented with a single alarm. The handshake alarm is set when the
  // handshake has not completed, the loss alarm is set when the loss detection
  // algorithm says to, and the TLP and  RTO alarms are set after that.
  // The TLP alarm is always set to run for under an RTO.
  switch (GetRetransmissionMode()) {
    case HANDSHAKE_MODE:
      ++stats_->crypto_retransmit_count;
      RetransmitCryptoPackets();
      return;
    case LOSS_MODE: {
      ++stats_->loss_timeout_count;
      QuicByteCount bytes_in_flight = unacked_packets_.bytes_in_flight();
      InvokeLossDetection(clock_->Now());
      MaybeInvokeCongestionEvent(false, bytes_in_flight);
      return;
    }
    case TLP_MODE:
      // If no tail loss probe can be sent, because there are no retransmittable
      // packets, execute a conventional RTO to abandon old packets.
      ++stats_->tlp_count;
      ++consecutive_tlp_count_;
      pending_timer_transmission_count_ = 1;
      // TLPs prefer sending new data instead of retransmitting data, so
      // give the connection a chance to write before completing the TLP.
      return;
    case RTO_MODE:
      ++stats_->rto_count;
      RetransmitRtoPackets();
      if (network_change_visitor_ != nullptr &&
          consecutive_rto_count_ == kMinTimeoutsBeforePathDegrading) {
        network_change_visitor_->OnPathDegrading();
      }
      return;
  }
}

void QuicSentPacketManager::RetransmitCryptoPackets() {
  DCHECK_EQ(HANDSHAKE_MODE, GetRetransmissionMode());
  ++consecutive_crypto_retransmission_count_;
  bool packet_retransmitted = false;
  QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
  for (QuicUnackedPacketMap::const_iterator it = unacked_packets_.begin();
       it != unacked_packets_.end(); ++it, ++packet_number) {
    // Only retransmit frames which are in flight, and therefore have been sent.
    if (!it->in_flight || it->retransmittable_frames.empty() ||
        !it->has_crypto_handshake) {
      continue;
    }
    packet_retransmitted = true;
    MarkForRetransmission(packet_number, HANDSHAKE_RETRANSMISSION);
    ++pending_timer_transmission_count_;
  }
  DCHECK(packet_retransmitted) << "No crypto packets found to retransmit.";
}

bool QuicSentPacketManager::MaybeRetransmitTailLossProbe() {
  if (pending_timer_transmission_count_ == 0) {
    return false;
  }
  QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
  for (QuicUnackedPacketMap::const_iterator it = unacked_packets_.begin();
       it != unacked_packets_.end(); ++it, ++packet_number) {
    // Only retransmit frames which are in flight, and therefore have been sent.
    if (!it->in_flight || it->retransmittable_frames.empty()) {
      continue;
    }
    if (!handshake_confirmed_) {
      DCHECK(!it->has_crypto_handshake);
    }
    MarkForRetransmission(packet_number, TLP_RETRANSMISSION);
    return true;
  }
  DLOG(ERROR)
      << "No retransmittable packets, so RetransmitOldestPacket failed.";
  return false;
}

void QuicSentPacketManager::RetransmitRtoPackets() {
  QUIC_BUG_IF(pending_timer_transmission_count_ > 0)
      << "Retransmissions already queued:" << pending_timer_transmission_count_;
  // Mark two packets for retransmission.
  QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
  for (QuicUnackedPacketMap::const_iterator it = unacked_packets_.begin();
       it != unacked_packets_.end(); ++it, ++packet_number) {
    if (!it->retransmittable_frames.empty() &&
        pending_timer_transmission_count_ < kMaxRetransmissionsOnTimeout) {
      MarkForRetransmission(packet_number, RTO_RETRANSMISSION);
      ++pending_timer_transmission_count_;
    }
    // Abandon non-retransmittable data that's in flight to ensure it doesn't
    // fill up the congestion window.
    const bool has_retransmissions = it->retransmission != 0;
    if (it->retransmittable_frames.empty() && it->in_flight &&
        !has_retransmissions) {
      // Log only for non-retransmittable data.
      // Retransmittable data is marked as lost during loss detection, and will
      // be logged later.
      unacked_packets_.RemoveFromInFlight(packet_number);
      if (debug_delegate_ != nullptr) {
        debug_delegate_->OnPacketLoss(packet_number, RTO_RETRANSMISSION,
                                      clock_->Now());
      }
    }
  }
  if (pending_timer_transmission_count_ > 0) {
    if (consecutive_rto_count_ == 0) {
      first_rto_transmission_ = unacked_packets_.largest_sent_packet() + 1;
    }
    ++consecutive_rto_count_;
  }
}

QuicSentPacketManager::RetransmissionTimeoutMode
QuicSentPacketManager::GetRetransmissionMode() const {
  DCHECK(unacked_packets_.HasInFlightPackets());
  if (!handshake_confirmed_ && unacked_packets_.HasPendingCryptoPackets()) {
    return HANDSHAKE_MODE;
  }
  if (loss_algorithm_->GetLossTimeout() != QuicTime::Zero()) {
    return LOSS_MODE;
  }
  if (consecutive_tlp_count_ < max_tail_loss_probes_) {
    if (unacked_packets_.HasUnackedRetransmittableFrames()) {
      return TLP_MODE;
    }
  }
  return RTO_MODE;
}

void QuicSentPacketManager::InvokeLossDetection(QuicTime time) {
  loss_algorithm_->DetectLosses(unacked_packets_, time, rtt_stats_,
                                &packets_lost_);
  for (const pair<QuicPacketNumber, QuicByteCount>& pair : packets_lost_) {
    ++stats_->packets_lost;
    if (debug_delegate_ != nullptr) {
      debug_delegate_->OnPacketLoss(pair.first, LOSS_RETRANSMISSION, time);
    }

    // TODO(ianswett): This could be optimized.
    if (unacked_packets_.HasRetransmittableFrames(pair.first)) {
      MarkForRetransmission(pair.first, LOSS_RETRANSMISSION);
    } else {
      // Since we will not retransmit this, we need to remove it from
      // unacked_packets_.   This is either the current transmission of
      // a packet whose previous transmission has been acked or a packet that
      // has been TLP retransmitted.
      unacked_packets_.RemoveFromInFlight(pair.first);
    }
  }
}

bool QuicSentPacketManager::MaybeUpdateRTT(const QuicAckFrame& ack_frame,
                                           QuicTime ack_receive_time) {
  // We rely on ack_delay_time to compute an RTT estimate, so we
  // only update rtt when the largest observed gets acked.
  // NOTE: If ack is a truncated ack, then the largest observed is in fact
  // unacked, and may cause an RTT sample to be taken.
  if (!unacked_packets_.IsUnacked(ack_frame.largest_observed)) {
    return false;
  }
  // We calculate the RTT based on the highest ACKed packet number, the lower
  // packet numbers will include the ACK aggregation delay.
  const TransmissionInfo& transmission_info =
      unacked_packets_.GetTransmissionInfo(ack_frame.largest_observed);
  // Ensure the packet has a valid sent time.
  if (transmission_info.sent_time == QuicTime::Zero()) {
    QUIC_BUG << "Acked packet has zero sent time, largest_observed:"
             << ack_frame.largest_observed;
    return false;
  }

  QuicTime::Delta send_delta =
      ack_receive_time.Subtract(transmission_info.sent_time);
  rtt_stats_.UpdateRtt(send_delta, ack_frame.ack_delay_time, ack_receive_time);

  if (network_change_visitor_ != nullptr) {
    network_change_visitor_->OnRttChange();
  }

  return true;
}

QuicTime::Delta QuicSentPacketManager::TimeUntilSend(
    QuicTime now,
    HasRetransmittableData retransmittable) {
  // The TLP logic is entirely contained within QuicSentPacketManager, so the
  // send algorithm does not need to be consulted.
  if (pending_timer_transmission_count_ > 0) {
    return QuicTime::Delta::Zero();
  }
  return send_algorithm_->TimeUntilSend(now,
                                        unacked_packets_.bytes_in_flight());
}

// Uses a 25ms delayed ack timer. Also helps with better signaling
// in low-bandwidth (< ~384 kbps), where an ack is sent per packet.
// Ensures that the Delayed Ack timer is always set to a value lesser
// than the retransmission timer's minimum value (MinRTO). We want the
// delayed ack to get back to the QUIC peer before the sender's
// retransmission timer triggers.  Since we do not know the
// reverse-path one-way delay, we assume equal delays for forward and
// reverse paths, and ensure that the timer is set to less than half
// of the MinRTO.
// There may be a value in making this delay adaptive with the help of
// the sender and a signaling mechanism -- if the sender uses a
// different MinRTO, we may get spurious retransmissions. May not have
// any benefits, but if the delayed ack becomes a significant source
// of (likely, tail) latency, then consider such a mechanism.
const QuicTime::Delta QuicSentPacketManager::DelayedAckTime() const {
  return QuicTime::Delta::FromMilliseconds(
      min(kMaxDelayedAckTimeMs, kMinRetransmissionTimeMs / 2));
}

const QuicTime QuicSentPacketManager::GetRetransmissionTime() const {
  // Don't set the timer if there are no packets in flight or we've already
  // queued a tlp transmission and it hasn't been sent yet.
  if (!unacked_packets_.HasInFlightPackets() ||
      pending_timer_transmission_count_ > 0) {
    return QuicTime::Zero();
  }
  switch (GetRetransmissionMode()) {
    case HANDSHAKE_MODE:
      return clock_->ApproximateNow().Add(GetCryptoRetransmissionDelay());
    case LOSS_MODE:
      return loss_algorithm_->GetLossTimeout();
    case TLP_MODE: {
      // TODO(ianswett): When CWND is available, it would be preferable to
      // set the timer based on the earliest retransmittable packet.
      // Base the updated timer on the send time of the last packet.
      const QuicTime sent_time = unacked_packets_.GetLastPacketSentTime();
      const QuicTime tlp_time = sent_time.Add(GetTailLossProbeDelay());
      // Ensure the TLP timer never gets set to a time in the past.
      return QuicTime::Max(clock_->ApproximateNow(), tlp_time);
    }
    case RTO_MODE: {
      // The RTO is based on the first outstanding packet.
      const QuicTime sent_time = unacked_packets_.GetLastPacketSentTime();
      QuicTime rto_time = sent_time.Add(GetRetransmissionDelay());
      // Wait for TLP packets to be acked before an RTO fires.
      QuicTime tlp_time =
          unacked_packets_.GetLastPacketSentTime().Add(GetTailLossProbeDelay());
      return QuicTime::Max(tlp_time, rto_time);
    }
  }
  DCHECK(false);
  return QuicTime::Zero();
}

const QuicTime::Delta QuicSentPacketManager::GetCryptoRetransmissionDelay()
    const {
  // This is equivalent to the TailLossProbeDelay, but slightly more aggressive
  // because crypto handshake messages don't incur a delayed ack time.
  QuicTime::Delta srtt = rtt_stats_.smoothed_rtt();
  if (srtt.IsZero()) {
    srtt = QuicTime::Delta::FromMicroseconds(rtt_stats_.initial_rtt_us());
  }
  int64_t delay_ms = max(kMinHandshakeTimeoutMs,
                         static_cast<int64_t>(1.5 * srtt.ToMilliseconds()));
  return QuicTime::Delta::FromMilliseconds(
      delay_ms << consecutive_crypto_retransmission_count_);
}

const QuicTime::Delta QuicSentPacketManager::GetTailLossProbeDelay() const {
  QuicTime::Delta srtt = rtt_stats_.smoothed_rtt();
  if (srtt.IsZero()) {
    srtt = QuicTime::Delta::FromMicroseconds(rtt_stats_.initial_rtt_us());
  }
  if (enable_half_rtt_tail_loss_probe_ && consecutive_tlp_count_ == 0u) {
    return QuicTime::Delta::FromMilliseconds(
        max(kMinTailLossProbeTimeoutMs,
            static_cast<int64_t>(0.5 * srtt.ToMilliseconds())));
  }
  if (!unacked_packets_.HasMultipleInFlightPackets()) {
    return QuicTime::Delta::Max(
        srtt.Multiply(2),
        srtt.Multiply(1.5).Add(
            QuicTime::Delta::FromMilliseconds(kMinRetransmissionTimeMs / 2)));
  }
  return QuicTime::Delta::FromMilliseconds(
      max(kMinTailLossProbeTimeoutMs,
          static_cast<int64_t>(2 * srtt.ToMilliseconds())));
}

const QuicTime::Delta QuicSentPacketManager::GetRetransmissionDelay() const {
  QuicTime::Delta retransmission_delay = send_algorithm_->RetransmissionDelay();
  if (retransmission_delay.IsZero()) {
    // We are in the initial state, use default timeout values.
    retransmission_delay =
        QuicTime::Delta::FromMilliseconds(kDefaultRetransmissionTimeMs);
  } else if (retransmission_delay.ToMilliseconds() < kMinRetransmissionTimeMs) {
    retransmission_delay =
        QuicTime::Delta::FromMilliseconds(kMinRetransmissionTimeMs);
  }

  // Calculate exponential back off.
  retransmission_delay = retransmission_delay.Multiply(
      1 << min<size_t>(consecutive_rto_count_, kMaxRetransmissions));

  if (retransmission_delay.ToMilliseconds() > kMaxRetransmissionTimeMs) {
    return QuicTime::Delta::FromMilliseconds(kMaxRetransmissionTimeMs);
  }
  return retransmission_delay;
}

const RttStats* QuicSentPacketManager::GetRttStats() const {
  return &rtt_stats_;
}

QuicBandwidth QuicSentPacketManager::BandwidthEstimate() const {
  // TODO(ianswett): Remove BandwidthEstimate from SendAlgorithmInterface
  // and implement the logic here.
  return send_algorithm_->BandwidthEstimate();
}

const QuicSustainedBandwidthRecorder&
QuicSentPacketManager::SustainedBandwidthRecorder() const {
  return sustained_bandwidth_recorder_;
}

QuicPacketCount QuicSentPacketManager::EstimateMaxPacketsInFlight(
    QuicByteCount max_packet_length) const {
  return send_algorithm_->GetCongestionWindow() / max_packet_length;
}

QuicPacketCount QuicSentPacketManager::GetCongestionWindowInTcpMss() const {
  return send_algorithm_->GetCongestionWindow() / kDefaultTCPMSS;
}

QuicByteCount QuicSentPacketManager::GetCongestionWindowInBytes() const {
  return send_algorithm_->GetCongestionWindow();
}

QuicPacketCount QuicSentPacketManager::GetSlowStartThresholdInTcpMss() const {
  return send_algorithm_->GetSlowStartThreshold() / kDefaultTCPMSS;
}

void QuicSentPacketManager::CancelRetransmissionsForStream(
    QuicStreamId stream_id) {
  unacked_packets_.CancelRetransmissionsForStream(stream_id);
  if (delegate_ != nullptr) {
    return;
  }
  PendingRetransmissionMap::iterator it = pending_retransmissions_.begin();
  while (it != pending_retransmissions_.end()) {
    if (HasRetransmittableFrames(it->first)) {
      ++it;
      continue;
    }
    it = pending_retransmissions_.erase(it);
  }
}

void QuicSentPacketManager::EnablePacing() {
  // TODO(ianswett): Replace with a method which wraps the send algorithm in a
  // pacer every time a new algorithm is set.
  if (using_pacing_) {
    return;
  }

  // Set up a pacing sender with a 1 millisecond alarm granularity, the same as
  // the default granularity of the Linux kernel's FQ qdisc.
  using_pacing_ = true;
  send_algorithm_.reset(new PacingSender(send_algorithm_.release(),
                                         QuicTime::Delta::FromMilliseconds(1),
                                         kInitialUnpacedBurst));
}

void QuicSentPacketManager::OnConnectionMigration(PeerAddressChangeType type) {
  if (type == PORT_CHANGE || type == IPV4_SUBNET_CHANGE) {
    // Rtt and cwnd do not need to be reset when the peer address change is
    // considered to be caused by NATs.
    return;
  }
  consecutive_rto_count_ = 0;
  consecutive_tlp_count_ = 0;
  rtt_stats_.OnConnectionMigration();
  send_algorithm_->OnConnectionMigration();
}

bool QuicSentPacketManager::InSlowStart() const {
  return send_algorithm_->InSlowStart();
}

TransmissionInfo* QuicSentPacketManager::GetMutableTransmissionInfo(
    QuicPacketNumber packet_number) {
  return unacked_packets_.GetMutableTransmissionInfo(packet_number);
}

void QuicSentPacketManager::RemoveObsoletePackets() {
  unacked_packets_.RemoveObsoletePackets();
}

}  // namespace net
