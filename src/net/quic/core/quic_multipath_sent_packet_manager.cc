// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_multipath_sent_packet_manager.h"

#include <cstdint>

#include "base/strings/string_number_conversions.h"
#include "net/quic/core/quic_bug_tracker.h"

using std::string;
using std::max;

namespace net {

QuicMultipathSentPacketManager::QuicMultipathSentPacketManager(
    QuicSentPacketManagerInterface* manager,
    QuicConnectionCloseDelegateInterface* delegate)
    : delegate_(delegate) {
  path_managers_info_.push_back(PathSentPacketManagerInfo(manager, ACTIVE));
}

QuicMultipathSentPacketManager::~QuicMultipathSentPacketManager() {
  for (PathSentPacketManagerInfo path_manager_info : path_managers_info_) {
    delete path_manager_info.manager;
  }
}

void QuicMultipathSentPacketManager::SetFromConfig(const QuicConfig& config) {
  for (PathSentPacketManagerInfo path_manager_info : path_managers_info_) {
    if (path_manager_info.manager != nullptr) {
      path_manager_info.manager->SetFromConfig(config);
    }
  }
}

void QuicMultipathSentPacketManager::ResumeConnectionState(
    const CachedNetworkParameters& cached_network_params,
    bool max_bandwidth_resumption) {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    OnUnrecoverablePathError(kDefaultPathId);
    return;
  }
  path_manager->ResumeConnectionState(cached_network_params,
                                      max_bandwidth_resumption);
}

void QuicMultipathSentPacketManager::SetNumOpenStreams(size_t num_streams) {
  for (PathSentPacketManagerInfo path_manager_info : path_managers_info_) {
    if (path_manager_info.manager != nullptr) {
      path_manager_info.manager->SetNumOpenStreams(num_streams);
    }
  }
}

void QuicMultipathSentPacketManager::SetMaxPacingRate(
    QuicBandwidth max_pacing_rate) {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    OnUnrecoverablePathError(kDefaultPathId);
    return;
  }
  path_manager->SetMaxPacingRate(max_pacing_rate);
}

void QuicMultipathSentPacketManager::SetHandshakeConfirmed() {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    OnUnrecoverablePathError(kDefaultPathId);
    return;
  }
  path_manager->SetHandshakeConfirmed();
}

void QuicMultipathSentPacketManager::OnIncomingAck(
    const QuicAckFrame& ack_frame,
    QuicTime ack_receive_time) {
  if (ack_frame.path_id >= path_managers_info_.size() ||
      path_managers_info_[ack_frame.path_id].state != ACTIVE) {
    return;
  }
  path_managers_info_[ack_frame.path_id].manager->OnIncomingAck(
      ack_frame, ack_receive_time);
}

void QuicMultipathSentPacketManager::RetransmitUnackedPackets(
    TransmissionType retransmission_type) {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    OnUnrecoverablePathError(kDefaultPathId);
    return;
  }
  path_manager->RetransmitUnackedPackets(retransmission_type);
}

bool QuicMultipathSentPacketManager::MaybeRetransmitTailLossProbe() {
  for (PathSentPacketManagerInfo path_manager_info : path_managers_info_) {
    if (path_manager_info.manager != nullptr &&
        path_manager_info.state == ACTIVE) {
      if (path_manager_info.manager->MaybeRetransmitTailLossProbe()) {
        return true;
      }
    }
  }
  return false;
}

void QuicMultipathSentPacketManager::NeuterUnencryptedPackets() {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    OnUnrecoverablePathError(kDefaultPathId);
    return;
  }
  path_manager->NeuterUnencryptedPackets();
}

bool QuicMultipathSentPacketManager::HasPendingRetransmissions() const {
  // TODO(fayang): Move pending_retransmissions_ from path sent packet manager
  // to multipath sent packet manager.
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  return path_manager != nullptr && path_manager->HasPendingRetransmissions();
}

PendingRetransmission
QuicMultipathSentPacketManager::NextPendingRetransmission() {
  // TODO(fayang): Move pending_retransmissions_ from path sent packet manager
  // to multipath sent packet manager.
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    OnUnrecoverablePathError(kDefaultPathId);
    QuicFrames retransmittable_frames;
    return PendingRetransmission(kInvalidPathId, 0u, NOT_RETRANSMISSION,
                                 retransmittable_frames, false, 0,
                                 ENCRYPTION_NONE, PACKET_1BYTE_PACKET_NUMBER);
  }
  return path_manager->NextPendingRetransmission();
}

bool QuicMultipathSentPacketManager::HasUnackedPackets() const {
  for (PathSentPacketManagerInfo path_manager_info : path_managers_info_) {
    if (path_manager_info.manager != nullptr &&
        path_manager_info.state == ACTIVE &&
        path_manager_info.manager->HasUnackedPackets()) {
      return true;
    }
  }
  return false;
}

QuicPacketNumber QuicMultipathSentPacketManager::GetLeastUnacked(
    QuicPathId path_id) const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForPath(path_id);
  if (path_manager == nullptr) {
    return 0;
  }
  return path_manager->GetLeastUnacked(path_id);
}

bool QuicMultipathSentPacketManager::OnPacketSent(
    SerializedPacket* serialized_packet,
    QuicPathId original_path_id,
    QuicPacketNumber original_packet_number,
    QuicTime sent_time,
    TransmissionType transmission_type,
    HasRetransmittableData has_retransmittable_data) {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(serialized_packet->path_id);
  // TODO(fayang): Handle packets retransmitted on different path.
  DCHECK(original_packet_number == 0 ||
         original_path_id == serialized_packet->path_id);
  if (path_manager == nullptr) {
    OnUnrecoverablePathError(serialized_packet->path_id);
    return false;
  }

  return path_manager->OnPacketSent(
      serialized_packet, original_path_id, original_packet_number, sent_time,
      transmission_type, has_retransmittable_data);
}

void QuicMultipathSentPacketManager::OnRetransmissionTimeout() {
  QuicPathId rto_path = DetermineRetransmissionTimeoutPath();
  DCHECK_NE(kInvalidPathId, rto_path);
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(rto_path);
  if (path_manager == nullptr) {
    OnUnrecoverablePathError(rto_path);
    return;
  }
  path_manager->OnRetransmissionTimeout();
}

QuicTime::Delta QuicMultipathSentPacketManager::TimeUntilSend(
    QuicTime now,
    QuicPathId* path_id) {
  QuicTime::Delta delay = QuicTime::Delta::Infinite();
  *path_id = kInvalidPathId;
  for (size_t i = 0; i < path_managers_info_.size(); ++i) {
    if (path_managers_info_[i].manager == nullptr ||
        path_managers_info_[i].state != ACTIVE) {
      continue;
    }

    QuicTime::Delta path_delay =
        path_managers_info_[i].manager->TimeUntilSend(now, path_id);
    if (!path_delay.IsInfinite() && path_delay < delay) {
      delay = path_delay;
      *path_id = i;
    }
  }
  DCHECK(*path_id == kInvalidPathId || !delay.IsInfinite());
  return delay;
}

const QuicTime QuicMultipathSentPacketManager::GetRetransmissionTime() const {
  QuicTime retransmission_time = QuicTime::Zero();
  for (PathSentPacketManagerInfo path_manager_info : path_managers_info_) {
    if (path_manager_info.manager == nullptr ||
        path_manager_info.state != ACTIVE) {
      continue;
    }
    QuicTime path_retransmission_time =
        path_manager_info.manager->GetRetransmissionTime();
    if (!path_retransmission_time.IsInitialized()) {
      continue;
    }
    if (!retransmission_time.IsInitialized() ||
        path_retransmission_time < retransmission_time) {
      retransmission_time = path_retransmission_time;
    }
  }

  return retransmission_time;
}

const RttStats* QuicMultipathSentPacketManager::GetRttStats() const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    return nullptr;
  }
  return path_manager->GetRttStats();
}

QuicBandwidth QuicMultipathSentPacketManager::BandwidthEstimate() const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    return QuicBandwidth::Zero();
  }
  return path_manager->BandwidthEstimate();
}

const QuicSustainedBandwidthRecorder*
QuicMultipathSentPacketManager::SustainedBandwidthRecorder() const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    return nullptr;
  }
  return path_manager->SustainedBandwidthRecorder();
}

QuicPacketCount QuicMultipathSentPacketManager::GetCongestionWindowInTcpMss()
    const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    return 0;
  }
  return path_manager->GetCongestionWindowInTcpMss();
}

QuicPacketCount QuicMultipathSentPacketManager::EstimateMaxPacketsInFlight(
    QuicByteCount max_packet_length) const {
  QuicPacketCount max_packets_in_flight = 0;
  for (PathSentPacketManagerInfo path_manager_info : path_managers_info_) {
    if (path_manager_info.manager != nullptr) {
      max_packets_in_flight =
          max(max_packets_in_flight,
              path_manager_info.manager->EstimateMaxPacketsInFlight(
                  max_packet_length));
    }
  }
  DCHECK_LT(0u, max_packets_in_flight);
  return max_packets_in_flight;
}

QuicByteCount QuicMultipathSentPacketManager::GetCongestionWindowInBytes()
    const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    return 0;
  }
  return path_manager->GetCongestionWindowInBytes();
}

QuicPacketCount QuicMultipathSentPacketManager::GetSlowStartThresholdInTcpMss()
    const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    return 0;
  }
  return path_manager->GetSlowStartThresholdInTcpMss();
}

string QuicMultipathSentPacketManager::GetDebugState() const {
  string debug_state_by_path;
  for (size_t i = 0; i < path_managers_info_.size(); ++i) {
    if (path_managers_info_[i].manager == nullptr ||
        path_managers_info_[i].state != ACTIVE) {
      continue;
    }
    const string& debug_state = path_managers_info_[i].manager->GetDebugState();
    if (debug_state.empty()) {
      continue;
    }
    debug_state_by_path =
        debug_state_by_path + "[" + base::IntToString(i) + "]:" + debug_state;
  }
  return debug_state_by_path;
}

void QuicMultipathSentPacketManager::CancelRetransmissionsForStream(
    QuicStreamId stream_id) {
  for (PathSentPacketManagerInfo path_manager_info : path_managers_info_) {
    if (path_manager_info.manager != nullptr) {
      path_manager_info.manager->CancelRetransmissionsForStream(stream_id);
    }
  }
}

void QuicMultipathSentPacketManager::OnConnectionMigration(
    QuicPathId path_id,
    PeerAddressChangeType type) {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(path_id);
  if (path_manager == nullptr) {
    OnUnrecoverablePathError(path_id);
    return;
  }
  path_manager->OnConnectionMigration(path_id, type);
}

bool QuicMultipathSentPacketManager::IsHandshakeConfirmed() const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  return path_manager != nullptr && path_manager->IsHandshakeConfirmed();
}

void QuicMultipathSentPacketManager::SetDebugDelegate(
    DebugDelegate* debug_delegate) {
  for (PathSentPacketManagerInfo path_manager_info : path_managers_info_) {
    if (path_manager_info.manager == nullptr) {
      continue;
    }
    path_manager_info.manager->SetDebugDelegate(debug_delegate);
  }
}

QuicPacketNumber QuicMultipathSentPacketManager::GetLargestObserved(
    QuicPathId path_id) const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForPath(path_id);
  if (path_manager == nullptr) {
    return 0;
  }
  return path_manager->GetLargestObserved(path_id);
}

QuicPacketNumber QuicMultipathSentPacketManager::GetLargestSentPacket(
    QuicPathId path_id) const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForPath(path_id);
  if (path_manager == nullptr) {
    return 0;
  }
  return path_manager->GetLargestSentPacket(path_id);
}

QuicPacketNumber QuicMultipathSentPacketManager::GetLeastPacketAwaitedByPeer(
    QuicPathId path_id) const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForPath(path_id);
  if (path_manager == nullptr) {
    return 0;
  }
  return path_manager->GetLeastPacketAwaitedByPeer(path_id);
}

void QuicMultipathSentPacketManager::SetNetworkChangeVisitor(
    NetworkChangeVisitor* visitor) {
  for (PathSentPacketManagerInfo path_manager_info : path_managers_info_) {
    if (path_manager_info.manager == nullptr ||
        path_manager_info.state != ACTIVE) {
      continue;
    }
    path_manager_info.manager->SetNetworkChangeVisitor(visitor);
  }
}

bool QuicMultipathSentPacketManager::InSlowStart() const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  return path_manager != nullptr && path_manager->InSlowStart();
}

size_t QuicMultipathSentPacketManager::GetConsecutiveRtoCount() const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    return 0;
  }
  return path_manager->GetConsecutiveRtoCount();
}
size_t QuicMultipathSentPacketManager::GetConsecutiveTlpCount() const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForActivePath(kDefaultPathId);
  if (path_manager == nullptr) {
    return 0;
  }
  return path_manager->GetConsecutiveTlpCount();
}

QuicMultipathSentPacketManager::PathSentPacketManagerInfo::
    PathSentPacketManagerInfo()
    : manager(nullptr), state(CLOSING) {}

QuicMultipathSentPacketManager::PathSentPacketManagerInfo::
    PathSentPacketManagerInfo(QuicSentPacketManagerInterface* manager,
                              PathSentPacketManagerState state)
    : manager(manager), state(state) {}

QuicMultipathSentPacketManager::PathSentPacketManagerInfo::
    PathSentPacketManagerInfo(const PathSentPacketManagerInfo& other) = default;

QuicSentPacketManagerInterface*
QuicMultipathSentPacketManager::MaybeGetSentPacketManagerForPath(
    QuicPathId path_id) const {
  if (path_id >= path_managers_info_.size() ||
      path_managers_info_[path_id].manager == nullptr) {
    QUIC_BUG << "Sent packet manager of path: (" + base::IntToString(path_id) +
                    ") must exist but does not.";
    return nullptr;
  }

  return path_managers_info_[path_id].manager;
}

QuicSentPacketManagerInterface*
QuicMultipathSentPacketManager::MaybeGetSentPacketManagerForActivePath(
    QuicPathId path_id) const {
  QuicSentPacketManagerInterface* path_manager =
      MaybeGetSentPacketManagerForPath(path_id);
  if (path_manager == nullptr) {
    return nullptr;
  }
  if (path_managers_info_[path_id].state != ACTIVE) {
    QUIC_BUG << "Sent packet manager of path: (" + base::IntToString(path_id) +
                    ") must be active but is not.";
    return nullptr;
  }

  return path_manager;
}

QuicPathId QuicMultipathSentPacketManager::DetermineRetransmissionTimeoutPath()
    const {
  QuicTime retransmission_time = QuicTime::Zero();
  QuicPathId rto_path = kInvalidPathId;
  for (size_t i = 0; i < path_managers_info_.size(); ++i) {
    if (path_managers_info_[i].manager == nullptr ||
        path_managers_info_[i].state != ACTIVE) {
      continue;
    }
    QuicTime path_retransmission_time =
        path_managers_info_[i].manager->GetRetransmissionTime();
    if (!path_retransmission_time.IsInitialized()) {
      continue;
    }
    if (!retransmission_time.IsInitialized() ||
        path_retransmission_time < retransmission_time) {
      retransmission_time = path_retransmission_time;
      rto_path = i;
    }
  }
  return rto_path;
}

void QuicMultipathSentPacketManager::OnUnrecoverablePathError(
    QuicPathId path_id) {
  if (MaybeGetSentPacketManagerForPath(path_id) == nullptr) {
    const string error_details = "Sent packet manager of path: (" +
                                 base::IntToString(path_id) +
                                 ") must exist but does not.";
    delegate_->OnUnrecoverableError(QUIC_MULTIPATH_PATH_DOES_NOT_EXIST,
                                    error_details,
                                    ConnectionCloseSource::FROM_SELF);
    return;
  }
  const string error_details = "Sent packet manager of path: (" +
                               base::IntToString(path_id) +
                               ") must be active but is not.";
  delegate_->OnUnrecoverableError(QUIC_MULTIPATH_PATH_NOT_ACTIVE, error_details,
                                  ConnectionCloseSource::FROM_SELF);
}

void QuicMultipathSentPacketManager::OnApplicationLimited() {
  for (PathSentPacketManagerInfo& path_manager_info : path_managers_info_) {
    if (path_manager_info.manager == nullptr ||
        path_manager_info.state != ACTIVE) {
      continue;
    }
    path_manager_info.manager->OnApplicationLimited();
  }
}

}  // namespace net
