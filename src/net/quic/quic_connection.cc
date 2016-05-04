// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_connection.h"

#include <string.h>
#include <sys/types.h>

#include <algorithm>
#include <iterator>
#include <limits>
#include <memory>
#include <set>
#include <utility>

#include "base/format_macros.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/metrics/histogram_macros.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "net/base/address_family.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/proto/cached_network_parameters.pb.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_packet_generator.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;
using base::StringPrintf;
using std::list;
using std::make_pair;
using std::max;
using std::min;
using std::numeric_limits;
using std::set;
using std::string;
using std::vector;

namespace net {

class QuicDecrypter;
class QuicEncrypter;

namespace {

// The largest gap in packets we'll accept without closing the connection.
// This will likely have to be tuned.
const QuicPacketNumber kMaxPacketGap = 5000;

// Maximum number of acks received before sending an ack in response.
const QuicPacketCount kMaxPacketsReceivedBeforeAckSend = 20;

// Maximum number of retransmittable packets received before sending an ack.
const QuicPacketCount kDefaultRetransmittablePacketsBeforeAck = 2;
// Minimum number of packets received before ack decimation is enabled.
// This intends to avoid the beginning of slow start, when CWNDs may be
// rapidly increasing.
const QuicPacketCount kMinReceivedBeforeAckDecimation = 100;
// Wait for up to 10 retransmittable packets before sending an ack.
const QuicPacketCount kMaxRetransmittablePacketsBeforeAck = 10;
// One quarter RTT delay when doing ack decimation.
const float kAckDecimationDelay = 0.25;
// One eighth RTT delay when doing ack decimation.
const float kShortAckDecimationDelay = 0.125;

bool Near(QuicPacketNumber a, QuicPacketNumber b) {
  QuicPacketNumber delta = (a > b) ? a - b : b - a;
  return delta <= kMaxPacketGap;
}

bool IsInitializedIPEndPoint(const IPEndPoint& address) {
  return net::GetAddressFamily(address.address()) !=
         net::ADDRESS_FAMILY_UNSPECIFIED;
}

// An alarm that is scheduled to send an ack if a timeout occurs.
class AckAlarm : public QuicAlarm::Delegate {
 public:
  explicit AckAlarm(QuicConnection* connection) : connection_(connection) {}

  void OnAlarm() override {
    DCHECK(connection_->ack_frame_updated());
    QuicConnection::ScopedPacketBundler bundler(connection_,
                                                QuicConnection::SEND_ACK);
  }

 private:
  QuicConnection* connection_;

  DISALLOW_COPY_AND_ASSIGN(AckAlarm);
};

// This alarm will be scheduled any time a data-bearing packet is sent out.
// When the alarm goes off, the connection checks to see if the oldest packets
// have been acked, and retransmit them if they have not.
class RetransmissionAlarm : public QuicAlarm::Delegate {
 public:
  explicit RetransmissionAlarm(QuicConnection* connection)
      : connection_(connection) {}

  void OnAlarm() override { connection_->OnRetransmissionTimeout(); }

 private:
  QuicConnection* connection_;

  DISALLOW_COPY_AND_ASSIGN(RetransmissionAlarm);
};

// An alarm that is scheduled when the SentPacketManager requires a delay
// before sending packets and fires when the packet may be sent.
class SendAlarm : public QuicAlarm::Delegate {
 public:
  explicit SendAlarm(QuicConnection* connection) : connection_(connection) {}

  void OnAlarm() override { connection_->WriteAndBundleAcksIfNotBlocked(); }

 private:
  QuicConnection* connection_;

  DISALLOW_COPY_AND_ASSIGN(SendAlarm);
};

class TimeoutAlarm : public QuicAlarm::Delegate {
 public:
  explicit TimeoutAlarm(QuicConnection* connection) : connection_(connection) {}

  void OnAlarm() override { connection_->CheckForTimeout(); }

 private:
  QuicConnection* connection_;

  DISALLOW_COPY_AND_ASSIGN(TimeoutAlarm);
};

class PingAlarm : public QuicAlarm::Delegate {
 public:
  explicit PingAlarm(QuicConnection* connection) : connection_(connection) {}

  void OnAlarm() override { connection_->OnPingTimeout(); }

 private:
  QuicConnection* connection_;

  DISALLOW_COPY_AND_ASSIGN(PingAlarm);
};

class MtuDiscoveryAlarm : public QuicAlarm::Delegate {
 public:
  explicit MtuDiscoveryAlarm(QuicConnection* connection)
      : connection_(connection) {}

  void OnAlarm() override { connection_->DiscoverMtu(); }

 private:
  QuicConnection* connection_;

  DISALLOW_COPY_AND_ASSIGN(MtuDiscoveryAlarm);
};

// Listens for acks of MTU discovery packets and raises the maximum packet size
// of the connection if the probe succeeds.
class MtuDiscoveryAckListener : public QuicAckListenerInterface {
 public:
  MtuDiscoveryAckListener(QuicConnection* connection, QuicByteCount probe_size)
      : connection_(connection), probe_size_(probe_size) {}

  void OnPacketAcked(int /*acked_bytes*/,
                     QuicTime::Delta /*ack delay time*/) override {
    // MTU discovery packets are not retransmittable, so it must be acked.
    MaybeIncreaseMtu();
  }

  void OnPacketRetransmitted(int /*retransmitted_bytes*/) override {}

 protected:
  // MtuDiscoveryAckListener is ref counted.
  ~MtuDiscoveryAckListener() override {}

 private:
  void MaybeIncreaseMtu() {
    if (probe_size_ > connection_->max_packet_length()) {
      connection_->SetMaxPacketLength(probe_size_);
    }
  }

  QuicConnection* connection_;
  QuicByteCount probe_size_;

  DISALLOW_COPY_AND_ASSIGN(MtuDiscoveryAckListener);
};

}  // namespace

#define ENDPOINT \
  (perspective_ == Perspective::IS_SERVER ? "Server: " : "Client: ")

QuicConnection::QuicConnection(QuicConnectionId connection_id,
                               IPEndPoint address,
                               QuicConnectionHelperInterface* helper,
                               QuicAlarmFactory* alarm_factory,
                               QuicPacketWriter* writer,
                               bool owns_writer,
                               Perspective perspective,
                               const QuicVersionVector& supported_versions)
    : framer_(supported_versions,
              helper->GetClock()->ApproximateNow(),
              perspective),
      helper_(helper),
      alarm_factory_(alarm_factory),
      per_packet_options_(nullptr),
      writer_(writer),
      owns_writer_(owns_writer),
      encryption_level_(ENCRYPTION_NONE),
      has_forward_secure_encrypter_(false),
      first_required_forward_secure_packet_(0),
      clock_(helper->GetClock()),
      random_generator_(helper->GetRandomGenerator()),
      connection_id_(connection_id),
      peer_address_(address),
      active_peer_migration_type_(NO_CHANGE),
      highest_packet_sent_before_peer_migration_(0),
      last_packet_decrypted_(false),
      last_size_(0),
      current_packet_data_(nullptr),
      last_decrypted_packet_level_(ENCRYPTION_NONE),
      should_last_packet_instigate_acks_(false),
      largest_seen_packet_with_ack_(0),
      largest_seen_packet_with_stop_waiting_(0),
      max_undecryptable_packets_(0),
      pending_version_negotiation_packet_(false),
      save_crypto_packets_as_termination_packets_(false),
      idle_timeout_connection_close_behavior_(
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET),
      close_connection_after_five_rtos_(false),
      received_packet_manager_(&stats_),
      ack_queued_(false),
      num_retransmittable_packets_received_since_last_ack_sent_(0),
      last_ack_had_missing_packets_(false),
      num_packets_received_since_last_ack_sent_(0),
      stop_waiting_count_(0),
      ack_mode_(TCP_ACKING),
      ack_decimation_delay_(kAckDecimationDelay),
      delay_setting_retransmission_alarm_(false),
      pending_retransmission_alarm_(false),
      defer_send_in_response_to_packets_(false),
      arena_(),
      ack_alarm_(
          alarm_factory_->CreateAlarm(arena_.New<AckAlarm>(this), &arena_)),
      retransmission_alarm_(
          alarm_factory_->CreateAlarm(arena_.New<RetransmissionAlarm>(this),
                                      &arena_)),
      send_alarm_(
          alarm_factory_->CreateAlarm(arena_.New<SendAlarm>(this), &arena_)),
      resume_writes_alarm_(
          alarm_factory_->CreateAlarm(arena_.New<SendAlarm>(this), &arena_)),
      timeout_alarm_(
          alarm_factory_->CreateAlarm(arena_.New<TimeoutAlarm>(this), &arena_)),
      ping_alarm_(
          alarm_factory_->CreateAlarm(arena_.New<PingAlarm>(this), &arena_)),
      mtu_discovery_alarm_(
          alarm_factory_->CreateAlarm(arena_.New<MtuDiscoveryAlarm>(this),
                                      &arena_)),
      visitor_(nullptr),
      debug_visitor_(nullptr),
      packet_generator_(connection_id_,
                        &framer_,
                        random_generator_,
                        helper->GetBufferAllocator(),
                        this),
      idle_network_timeout_(QuicTime::Delta::Infinite()),
      handshake_timeout_(QuicTime::Delta::Infinite()),
      time_of_last_received_packet_(clock_->ApproximateNow()),
      time_of_last_sent_new_packet_(clock_->ApproximateNow()),
      last_send_for_timeout_(clock_->ApproximateNow()),
      packet_number_of_last_sent_packet_(0),
      sent_packet_manager_(
          perspective,
          kDefaultPathId,
          clock_,
          &stats_,
          FLAGS_quic_use_bbr_congestion_control ? kBBR : kCubic,
          FLAGS_quic_use_time_loss_detection ? kTime : kNack,
          /*delegate=*/nullptr),
      version_negotiation_state_(START_NEGOTIATION),
      perspective_(perspective),
      connected_(true),
      can_truncate_connection_ids_(true),
      mtu_discovery_target_(0),
      mtu_probe_count_(0),
      packets_between_mtu_probes_(kPacketsBetweenMtuProbesBase),
      next_mtu_probe_at_(kPacketsBetweenMtuProbesBase),
      largest_received_packet_size_(0),
      goaway_sent_(false),
      goaway_received_(false),
      multipath_enabled_(false) {
  DVLOG(1) << ENDPOINT
           << "Created connection with connection_id: " << connection_id;
  framer_.set_visitor(this);
  framer_.set_received_entropy_calculator(&received_packet_manager_);
  last_stop_waiting_frame_.least_unacked = 0;
  stats_.connection_creation_time = clock_->ApproximateNow();
  sent_packet_manager_.set_network_change_visitor(this);
  // Allow the packet writer to potentially reduce the packet size to a value
  // even smaller than kDefaultMaxPacketSize.
  SetMaxPacketLength(perspective_ == Perspective::IS_SERVER
                         ? kDefaultServerMaxPacketSize
                         : kDefaultMaxPacketSize);
}

QuicConnection::~QuicConnection() {
  if (owns_writer_) {
    delete writer_;
  }
  STLDeleteElements(&undecryptable_packets_);
  if (termination_packets_.get() != nullptr) {
    STLDeleteElements(termination_packets_.get());
  }
  ClearQueuedPackets();
}

void QuicConnection::ClearQueuedPackets() {
  for (QueuedPacketList::iterator it = queued_packets_.begin();
       it != queued_packets_.end(); ++it) {
    // Delete the buffer before calling ClearSerializedPacket, which sets
    // encrypted_buffer to nullptr.
    delete[] it->encrypted_buffer;
    QuicUtils::ClearSerializedPacket(&(*it));
  }
  queued_packets_.clear();
}

void QuicConnection::SetFromConfig(const QuicConfig& config) {
  if (config.negotiated()) {
    // Handshake complete, set handshake timeout to Infinite.
    SetNetworkTimeouts(QuicTime::Delta::Infinite(),
                       config.IdleConnectionStateLifetime());
    if (config.SilentClose()) {
      idle_timeout_connection_close_behavior_ =
          ConnectionCloseBehavior::SILENT_CLOSE;
    }
    if (FLAGS_quic_enable_multipath && config.MultipathEnabled()) {
      multipath_enabled_ = true;
    }
  } else {
    SetNetworkTimeouts(config.max_time_before_crypto_handshake(),
                       config.max_idle_time_before_crypto_handshake());
  }

  sent_packet_manager_.SetFromConfig(config);
  if (config.HasReceivedBytesForConnectionId() &&
      can_truncate_connection_ids_) {
    packet_generator_.SetConnectionIdLength(
        config.ReceivedBytesForConnectionId());
  }
  max_undecryptable_packets_ = config.max_undecryptable_packets();

  if (config.HasClientSentConnectionOption(kMTUH, perspective_)) {
    SetMtuDiscoveryTarget(kMtuDiscoveryTargetPacketSizeHigh);
  }
  if (config.HasClientSentConnectionOption(kMTUL, perspective_)) {
    SetMtuDiscoveryTarget(kMtuDiscoveryTargetPacketSizeLow);
  }
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnSetFromConfig(config);
  }
  if (config.HasClientSentConnectionOption(kACKD, perspective_)) {
    ack_mode_ = ACK_DECIMATION;
  }
  if (config.HasClientSentConnectionOption(kAKD2, perspective_)) {
    ack_mode_ = ACK_DECIMATION_WITH_REORDERING;
  }
  if (config.HasClientSentConnectionOption(kAKD3, perspective_)) {
    ack_mode_ = ACK_DECIMATION;
    ack_decimation_delay_ = kShortAckDecimationDelay;
  }
  if (config.HasClientSentConnectionOption(kAKD4, perspective_)) {
    ack_mode_ = ACK_DECIMATION_WITH_REORDERING;
    ack_decimation_delay_ = kShortAckDecimationDelay;
  }
  if (FLAGS_quic_enable_rto_timeout &&
      config.HasClientSentConnectionOption(k5RTO, perspective_)) {
    close_connection_after_five_rtos_ = true;
  }
}

void QuicConnection::OnSendConnectionState(
    const CachedNetworkParameters& cached_network_params) {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnSendConnectionState(cached_network_params);
  }
}

void QuicConnection::OnReceiveConnectionState(
    const CachedNetworkParameters& cached_network_params) {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnReceiveConnectionState(cached_network_params);
  }
}

void QuicConnection::ResumeConnectionState(
    const CachedNetworkParameters& cached_network_params,
    bool max_bandwidth_resumption) {
  sent_packet_manager_.ResumeConnectionState(cached_network_params,
                                             max_bandwidth_resumption);
}

void QuicConnection::SetNumOpenStreams(size_t num_streams) {
  sent_packet_manager_.SetNumOpenStreams(num_streams);
}

bool QuicConnection::SelectMutualVersion(
    const QuicVersionVector& available_versions) {
  // Try to find the highest mutual version by iterating over supported
  // versions, starting with the highest, and breaking out of the loop once we
  // find a matching version in the provided available_versions vector.
  const QuicVersionVector& supported_versions = framer_.supported_versions();
  for (size_t i = 0; i < supported_versions.size(); ++i) {
    const QuicVersion& version = supported_versions[i];
    if (ContainsValue(available_versions, version)) {
      framer_.set_version(version);
      return true;
    }
  }

  return false;
}

void QuicConnection::OnError(QuicFramer* framer) {
  // Packets that we can not or have not decrypted are dropped.
  // TODO(rch): add stats to measure this.
  if (!connected_ || last_packet_decrypted_ == false) {
    return;
  }
  CloseConnection(framer->error(), framer->detailed_error(),
                  ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

void QuicConnection::OnPacket() {
  last_packet_decrypted_ = false;
}

void QuicConnection::OnPublicResetPacket(const QuicPublicResetPacket& packet) {
  // Check that any public reset packet with a different connection ID that was
  // routed to this QuicConnection has been redirected before control reaches
  // here.  (Check for a bug regression.)
  DCHECK_EQ(connection_id_, packet.public_header.connection_id);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPublicResetPacket(packet);
  }
  const string error_details = "Received public reset.";
  DVLOG(1) << ENDPOINT << error_details;
  TearDownLocalConnectionState(QUIC_PUBLIC_RESET, error_details,
                               ConnectionCloseSource::FROM_PEER);
}

bool QuicConnection::OnProtocolVersionMismatch(QuicVersion received_version) {
  DVLOG(1) << ENDPOINT << "Received packet with mismatched version "
           << received_version;
  // TODO(satyamshekhar): Implement no server state in this mode.
  if (perspective_ == Perspective::IS_CLIENT) {
    const string error_details = "Protocol version mismatch.";
    QUIC_BUG << ENDPOINT << error_details;
    TearDownLocalConnectionState(QUIC_INTERNAL_ERROR, error_details,
                                 ConnectionCloseSource::FROM_SELF);
    return false;
  }
  DCHECK_NE(version(), received_version);

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnProtocolVersionMismatch(received_version);
  }

  switch (version_negotiation_state_) {
    case START_NEGOTIATION:
      if (!framer_.IsSupportedVersion(received_version)) {
        SendVersionNegotiationPacket();
        version_negotiation_state_ = NEGOTIATION_IN_PROGRESS;
        return false;
      }
      break;

    case NEGOTIATION_IN_PROGRESS:
      if (!framer_.IsSupportedVersion(received_version)) {
        SendVersionNegotiationPacket();
        return false;
      }
      break;

    case NEGOTIATED_VERSION:
      // Might be old packets that were sent by the client before the version
      // was negotiated. Drop these.
      return false;

    default:
      DCHECK(false);
  }

  version_negotiation_state_ = NEGOTIATED_VERSION;
  visitor_->OnSuccessfulVersionNegotiation(received_version);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnSuccessfulVersionNegotiation(received_version);
  }
  DVLOG(1) << ENDPOINT << "version negotiated " << received_version;

  // Store the new version.
  framer_.set_version(received_version);

  // TODO(satyamshekhar): Store the packet number of this packet and close the
  // connection if we ever received a packet with incorrect version and whose
  // packet number is greater.
  return true;
}

// Handles version negotiation for client connection.
void QuicConnection::OnVersionNegotiationPacket(
    const QuicVersionNegotiationPacket& packet) {
  // Check that any public reset packet with a different connection ID that was
  // routed to this QuicConnection has been redirected before control reaches
  // here.  (Check for a bug regression.)
  DCHECK_EQ(connection_id_, packet.connection_id);
  if (perspective_ == Perspective::IS_SERVER) {
    const string error_details = "Server receieved version negotiation packet.";
    QUIC_BUG << error_details;
    TearDownLocalConnectionState(QUIC_INTERNAL_ERROR, error_details,
                                 ConnectionCloseSource::FROM_SELF);
    return;
  }
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnVersionNegotiationPacket(packet);
  }

  if (version_negotiation_state_ != START_NEGOTIATION) {
    // Possibly a duplicate version negotiation packet.
    return;
  }

  if (ContainsValue(packet.versions, version())) {
    const string error_details =
        "Server already supports client's version and should have accepted the "
        "connection.";
    DLOG(WARNING) << error_details;
    TearDownLocalConnectionState(QUIC_INVALID_VERSION_NEGOTIATION_PACKET,
                                 error_details,
                                 ConnectionCloseSource::FROM_SELF);
    return;
  }

  if (!SelectMutualVersion(packet.versions)) {
    CloseConnection(QUIC_INVALID_VERSION, "No common version found.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  DVLOG(1) << ENDPOINT
           << "Negotiated version: " << QuicVersionToString(version());
  server_supported_versions_ = packet.versions;
  version_negotiation_state_ = NEGOTIATION_IN_PROGRESS;
  RetransmitUnackedPackets(ALL_UNACKED_RETRANSMISSION);
}

bool QuicConnection::OnUnauthenticatedPublicHeader(
    const QuicPacketPublicHeader& header) {
  if (header.connection_id == connection_id_) {
    return true;
  }

  ++stats_.packets_dropped;
  DVLOG(1) << ENDPOINT << "Ignoring packet from unexpected ConnectionId: "
           << header.connection_id << " instead of " << connection_id_;
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnIncorrectConnectionId(header.connection_id);
  }
  // If this is a server, the dispatcher routes each packet to the
  // QuicConnection responsible for the packet's connection ID.  So if control
  // arrives here and this is a server, the dispatcher must be malfunctioning.
  DCHECK_NE(Perspective::IS_SERVER, perspective_);
  return false;
}

bool QuicConnection::OnUnauthenticatedHeader(const QuicPacketHeader& header) {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnUnauthenticatedHeader(header);
  }

  // Check that any public reset packet with a different connection ID that was
  // routed to this QuicConnection has been redirected before control reaches
  // here.
  DCHECK_EQ(connection_id_, header.public_header.connection_id);

  // Multipath is not enabled, but a packet with multipath flag on is received.
  if (!multipath_enabled_ && header.public_header.multipath_flag) {
    const string error_details =
        "Received a packet with multipath flag but multipath is not enabled.";
    QUIC_BUG << error_details;
    CloseConnection(QUIC_BAD_MULTIPATH_FLAG, error_details,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  if (!packet_generator_.IsPendingPacketEmpty()) {
    // Incoming packets may change a queued ACK frame.
    const string error_details =
        "Pending frames must be serialized before incoming packets are "
        "processed.";
    QUIC_BUG << error_details;
    CloseConnection(QUIC_INTERNAL_ERROR, error_details,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  // If this packet has already been seen, or the sender has told us that it
  // will not be retransmitted, then stop processing the packet.
  if (!received_packet_manager_.IsAwaitingPacket(header.packet_number)) {
    DVLOG(1) << ENDPOINT << "Packet " << header.packet_number
             << " no longer being waited for.  Discarding.";
    if (debug_visitor_ != nullptr) {
      debug_visitor_->OnDuplicatePacket(header.packet_number);
    }
    ++stats_.packets_dropped;
    return false;
  }

  return true;
}

void QuicConnection::OnDecryptedPacket(EncryptionLevel level) {
  last_decrypted_packet_level_ = level;
  last_packet_decrypted_ = true;

  // If this packet was foward-secure encrypted and the forward-secure encrypter
  // is not being used, start using it.
  if (encryption_level_ != ENCRYPTION_FORWARD_SECURE &&
      has_forward_secure_encrypter_ && level == ENCRYPTION_FORWARD_SECURE) {
    SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  }
}

bool QuicConnection::OnPacketHeader(const QuicPacketHeader& header) {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPacketHeader(header);
  }

  // Will be decremented below if we fall through to return true.
  ++stats_.packets_dropped;

  if (!ProcessValidatedPacket(header)) {
    return false;
  }

  // Only migrate connection to a new peer address if a change is not underway.
  PeerAddressChangeType peer_migration_type =
      QuicUtils::DetermineAddressChangeType(peer_address_,
                                            last_packet_source_address_);
  if (active_peer_migration_type_ == NO_CHANGE &&
      peer_migration_type != NO_CHANGE) {
    StartPeerMigration(peer_migration_type);
  }

  --stats_.packets_dropped;
  DVLOG(1) << ENDPOINT << "Received packet header: " << header;
  last_header_ = header;
  DCHECK(connected_);
  return true;
}

bool QuicConnection::OnStreamFrame(const QuicStreamFrame& frame) {
  DCHECK(connected_);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnStreamFrame(frame);
  }
  if (frame.stream_id != kCryptoStreamId &&
      last_decrypted_packet_level_ == ENCRYPTION_NONE) {
    QUIC_BUG << ENDPOINT
             << "Received an unencrypted data frame: closing connection"
             << " packet_number:" << last_header_.packet_number
             << " stream_id:" << frame.stream_id
             << " received_packets:" << received_packet_manager_.ack_frame();
    CloseConnection(QUIC_UNENCRYPTED_STREAM_DATA,
                    "Unencrypted stream data seen.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  visitor_->OnStreamFrame(frame);
  visitor_->PostProcessAfterData();
  stats_.stream_bytes_received += frame.frame_length;
  should_last_packet_instigate_acks_ = true;
  return connected_;
}

bool QuicConnection::OnAckFrame(const QuicAckFrame& incoming_ack) {
  DCHECK(connected_);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnAckFrame(incoming_ack);
  }
  DVLOG(1) << ENDPOINT << "OnAckFrame: " << incoming_ack;

  if (last_header_.packet_number <= largest_seen_packet_with_ack_) {
    DVLOG(1) << ENDPOINT << "Received an old ack frame: ignoring";
    return true;
  }

  const char* error = ValidateAckFrame(incoming_ack);
  if (error != nullptr) {
    CloseConnection(QUIC_INVALID_ACK_DATA, error,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  if (send_alarm_->IsSet()) {
    send_alarm_->Cancel();
  }
  ProcessAckFrame(incoming_ack);
  if (incoming_ack.is_truncated) {
    should_last_packet_instigate_acks_ = true;
  }
  // If the peer is still waiting for a packet that we are no longer planning to
  // send, send an ack to raise the high water mark.
  if (!incoming_ack.missing_packets.Empty() &&
      GetLeastUnacked() > incoming_ack.missing_packets.Min()) {
    ++stop_waiting_count_;
  } else {
    stop_waiting_count_ = 0;
  }

  return connected_;
}

void QuicConnection::ProcessAckFrame(const QuicAckFrame& incoming_ack) {
  largest_seen_packet_with_ack_ = last_header_.packet_number;
  sent_packet_manager_.OnIncomingAck(incoming_ack,
                                     time_of_last_received_packet_);
  sent_entropy_manager_.ClearEntropyBefore(
      sent_packet_manager_.least_packet_awaited_by_peer() - 1);

  // Always reset the retransmission alarm when an ack comes in, since we now
  // have a better estimate of the current rtt than when it was set.
  SetRetransmissionAlarm();
}

void QuicConnection::ProcessStopWaitingFrame(
    const QuicStopWaitingFrame& stop_waiting) {
  largest_seen_packet_with_stop_waiting_ = last_header_.packet_number;
  received_packet_manager_.UpdatePacketInformationSentByPeer(stop_waiting);
}

bool QuicConnection::OnStopWaitingFrame(const QuicStopWaitingFrame& frame) {
  DCHECK(connected_);

  if (last_header_.packet_number <= largest_seen_packet_with_stop_waiting_) {
    DVLOG(1) << ENDPOINT << "Received an old stop waiting frame: ignoring";
    return true;
  }

  const char* error = ValidateStopWaitingFrame(frame);
  if (error != nullptr) {
    CloseConnection(QUIC_INVALID_STOP_WAITING_DATA, error,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnStopWaitingFrame(frame);
  }

  last_stop_waiting_frame_ = frame;
  return connected_;
}

bool QuicConnection::OnPaddingFrame(const QuicPaddingFrame& frame) {
  DCHECK(connected_);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPaddingFrame(frame);
  }
  return true;
}

bool QuicConnection::OnPingFrame(const QuicPingFrame& frame) {
  DCHECK(connected_);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPingFrame(frame);
  }
  should_last_packet_instigate_acks_ = true;
  return true;
}

const char* QuicConnection::ValidateAckFrame(const QuicAckFrame& incoming_ack) {
  if (incoming_ack.largest_observed > packet_generator_.packet_number()) {
    LOG(WARNING) << ENDPOINT << "Peer's observed unsent packet:"
                 << incoming_ack.largest_observed << " vs "
                 << packet_generator_.packet_number();
    // We got an error for data we have not sent.  Error out.
    return "Largest observed too high.";
  }

  if (incoming_ack.largest_observed < sent_packet_manager_.largest_observed()) {
    LOG(WARNING) << ENDPOINT << "Peer's largest_observed packet decreased:"
                 << incoming_ack.largest_observed << " vs "
                 << sent_packet_manager_.largest_observed()
                 << " packet_number:" << last_header_.packet_number
                 << " largest seen with ack:" << largest_seen_packet_with_ack_
                 << " connection_id: " << connection_id_;
    // A new ack has a diminished largest_observed value.  Error out.
    // If this was an old packet, we wouldn't even have checked.
    return "Largest observed too low.";
  }

  if (!incoming_ack.missing_packets.Empty() &&
      incoming_ack.missing_packets.Max() > incoming_ack.largest_observed) {
    LOG(WARNING) << ENDPOINT << "Peer sent missing packet: "
                 << incoming_ack.missing_packets.Max()
                 << " which is greater than largest observed: "
                 << incoming_ack.largest_observed;
    return "Missing packet higher than largest observed.";
  }

  if (!incoming_ack.missing_packets.Empty() &&
      incoming_ack.missing_packets.Min() <
          sent_packet_manager_.least_packet_awaited_by_peer()) {
    LOG(WARNING) << ENDPOINT << "Peer sent missing packet: "
                 << incoming_ack.missing_packets.Min()
                 << " which is smaller than least_packet_awaited_by_peer_: "
                 << sent_packet_manager_.least_packet_awaited_by_peer();
    return "Missing packet smaller than least awaited.";
  }

  if (!sent_entropy_manager_.IsValidEntropy(incoming_ack.largest_observed,
                                            incoming_ack.missing_packets,
                                            incoming_ack.entropy_hash)) {
    LOG(WARNING) << ENDPOINT << "Peer sent invalid entropy."
                 << " largest_observed:" << incoming_ack.largest_observed
                 << " last_received:" << last_header_.packet_number;
    return "Invalid entropy.";
  }

  return nullptr;
}

const char* QuicConnection::ValidateStopWaitingFrame(
    const QuicStopWaitingFrame& stop_waiting) {
  if (stop_waiting.least_unacked <
      received_packet_manager_.peer_least_packet_awaiting_ack()) {
    DLOG(ERROR) << ENDPOINT << "Peer's sent low least_unacked: "
                << stop_waiting.least_unacked << " vs "
                << received_packet_manager_.peer_least_packet_awaiting_ack();
    // We never process old ack frames, so this number should only increase.
    return "Least unacked too small.";
  }

  if (stop_waiting.least_unacked > last_header_.packet_number) {
    DLOG(ERROR) << ENDPOINT
                << "Peer sent least_unacked:" << stop_waiting.least_unacked
                << " greater than the enclosing packet number:"
                << last_header_.packet_number;
    return "Least unacked too large.";
  }

  return nullptr;
}

bool QuicConnection::OnRstStreamFrame(const QuicRstStreamFrame& frame) {
  DCHECK(connected_);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnRstStreamFrame(frame);
  }
  DVLOG(1) << ENDPOINT
           << "RST_STREAM_FRAME received for stream: " << frame.stream_id
           << " with error: "
           << QuicUtils::StreamErrorToString(frame.error_code);
  visitor_->OnRstStream(frame);
  visitor_->PostProcessAfterData();
  should_last_packet_instigate_acks_ = true;
  return connected_;
}

bool QuicConnection::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame& frame) {
  DCHECK(connected_);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnConnectionCloseFrame(frame);
  }
  DVLOG(1) << ENDPOINT
           << "Received ConnectionClose for connection: " << connection_id()
           << ", with error: " << QuicUtils::ErrorToString(frame.error_code)
           << " (" << frame.error_details << ")";
  TearDownLocalConnectionState(frame.error_code, frame.error_details,
                               ConnectionCloseSource::FROM_PEER);
  return connected_;
}

bool QuicConnection::OnGoAwayFrame(const QuicGoAwayFrame& frame) {
  DCHECK(connected_);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnGoAwayFrame(frame);
  }
  DVLOG(1) << ENDPOINT << "GOAWAY_FRAME received with last good stream: "
           << frame.last_good_stream_id
           << " and error: " << QuicUtils::ErrorToString(frame.error_code)
           << " and reason: " << frame.reason_phrase;

  goaway_received_ = true;
  visitor_->OnGoAway(frame);
  visitor_->PostProcessAfterData();
  should_last_packet_instigate_acks_ = true;
  return connected_;
}

bool QuicConnection::OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) {
  DCHECK(connected_);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnWindowUpdateFrame(frame);
  }
  DVLOG(1) << ENDPOINT
           << "WINDOW_UPDATE_FRAME received for stream: " << frame.stream_id
           << " with byte offset: " << frame.byte_offset;
  visitor_->OnWindowUpdateFrame(frame);
  visitor_->PostProcessAfterData();
  should_last_packet_instigate_acks_ = true;
  return connected_;
}

bool QuicConnection::OnBlockedFrame(const QuicBlockedFrame& frame) {
  DCHECK(connected_);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnBlockedFrame(frame);
  }
  DVLOG(1) << ENDPOINT
           << "BLOCKED_FRAME received for stream: " << frame.stream_id;
  visitor_->OnBlockedFrame(frame);
  visitor_->PostProcessAfterData();
  should_last_packet_instigate_acks_ = true;
  return connected_;
}

bool QuicConnection::OnPathCloseFrame(const QuicPathCloseFrame& frame) {
  DCHECK(connected_);
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPathCloseFrame(frame);
  }
  DVLOG(1) << ENDPOINT
           << "PATH_CLOSE_FRAME received for path: " << frame.path_id;
  OnPathClosed(frame.path_id);
  return connected_;
}

void QuicConnection::OnPacketComplete() {
  // Don't do anything if this packet closed the connection.
  if (!connected_) {
    ClearLastFrames();
    return;
  }

  DVLOG(1) << ENDPOINT << "Got packet " << last_header_.packet_number << " for "
           << last_header_.public_header.connection_id;

  // An ack will be sent if a missing retransmittable packet was received;
  const bool was_missing =
      should_last_packet_instigate_acks_ &&
      received_packet_manager_.IsMissing(last_header_.packet_number);

  // Record received to populate ack info correctly before processing stream
  // frames, since the processing may result in a response packet with a bundled
  // ack.
  received_packet_manager_.RecordPacketReceived(last_size_, last_header_,
                                                time_of_last_received_packet_);

  // Process stop waiting frames here, instead of inline, because the packet
  // needs to be considered 'received' before the entropy can be updated.
  if (last_stop_waiting_frame_.least_unacked > 0) {
    ProcessStopWaitingFrame(last_stop_waiting_frame_);
    if (!connected_) {
      return;
    }
  }

  MaybeQueueAck(was_missing);

  ClearLastFrames();
  MaybeCloseIfTooManyOutstandingPackets();
}

void QuicConnection::MaybeQueueAck(bool was_missing) {
  ++num_packets_received_since_last_ack_sent_;
  // Always send an ack every 20 packets in order to allow the peer to discard
  // information from the SentPacketManager and provide an RTT measurement.
  if (num_packets_received_since_last_ack_sent_ >=
      kMaxPacketsReceivedBeforeAckSend) {
    ack_queued_ = true;
  }

  // Determine whether the newly received packet was missing before recording
  // the received packet.
  // Ack decimation with reordering relies on the timer to send an ack, but if
  // missing packets we reported in the previous ack, send an ack immediately.
  if (was_missing && (ack_mode_ != ACK_DECIMATION_WITH_REORDERING ||
                      last_ack_had_missing_packets_)) {
    ack_queued_ = true;
  }

  if (should_last_packet_instigate_acks_ && !ack_queued_) {
    ++num_retransmittable_packets_received_since_last_ack_sent_;
    if (ack_mode_ != TCP_ACKING &&
        last_header_.packet_number > kMinReceivedBeforeAckDecimation) {
      // Ack up to 10 packets at once.
      if (num_retransmittable_packets_received_since_last_ack_sent_ >=
          kMaxRetransmittablePacketsBeforeAck) {
        ack_queued_ = true;
      } else if (!ack_alarm_->IsSet()) {
        // Wait the minimum of a quarter min_rtt and the delayed ack time.
        QuicTime::Delta ack_delay = QuicTime::Delta::Min(
            sent_packet_manager_.DelayedAckTime(),
            sent_packet_manager_.GetRttStats()->min_rtt().Multiply(
                ack_decimation_delay_));
        ack_alarm_->Set(clock_->ApproximateNow().Add(ack_delay));
      }
    } else {
      // Ack with a timer or every 2 packets by default.
      if (num_retransmittable_packets_received_since_last_ack_sent_ >=
          kDefaultRetransmittablePacketsBeforeAck) {
        ack_queued_ = true;
      } else if (!ack_alarm_->IsSet()) {
        ack_alarm_->Set(clock_->ApproximateNow().Add(
            sent_packet_manager_.DelayedAckTime()));
      }
    }

    // If there are new missing packets to report, send an ack immediately.
    if (received_packet_manager_.HasNewMissingPackets()) {
      if (ack_mode_ == ACK_DECIMATION_WITH_REORDERING) {
        // Wait the minimum of an eighth min_rtt and the existing ack time.
        QuicTime ack_time = clock_->ApproximateNow().Add(
            sent_packet_manager_.GetRttStats()->min_rtt().Multiply(0.125));
        if (!ack_alarm_->IsSet() || ack_alarm_->deadline() > ack_time) {
          ack_alarm_->Cancel();
          ack_alarm_->Set(ack_time);
        }
      } else {
        ack_queued_ = true;
      }
    }
  }

  if (ack_queued_) {
    ack_alarm_->Cancel();
  }
}

void QuicConnection::ClearLastFrames() {
  should_last_packet_instigate_acks_ = false;
  last_stop_waiting_frame_.least_unacked = 0;
}

void QuicConnection::MaybeCloseIfTooManyOutstandingPackets() {
  // This occurs if we don't discard old packets we've sent fast enough.
  // It's possible largest observed is less than least unacked.
  if (sent_packet_manager_.largest_observed() >
      (sent_packet_manager_.GetLeastUnacked() + kMaxTrackedPackets)) {
    CloseConnection(
        QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS,
        StringPrintf("More than %" PRIu64 " outstanding.", kMaxTrackedPackets),
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
  // This occurs if there are received packet gaps and the peer does not raise
  // the least unacked fast enough.
  if (received_packet_manager_.NumTrackedPackets() > kMaxTrackedPackets) {
    CloseConnection(
        QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS,
        StringPrintf("More than %" PRIu64 " outstanding.", kMaxTrackedPackets),
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
}

const QuicFrame QuicConnection::GetUpdatedAckFrame() {
  return received_packet_manager_.GetUpdatedAckFrame(clock_->ApproximateNow());
}

void QuicConnection::PopulateStopWaitingFrame(
    QuicStopWaitingFrame* stop_waiting) {
  stop_waiting->least_unacked = GetLeastUnacked();
  stop_waiting->entropy_hash = sent_entropy_manager_.GetCumulativeEntropy(
      stop_waiting->least_unacked - 1);
}

QuicPacketNumber QuicConnection::GetLeastUnacked() const {
  return sent_packet_manager_.GetLeastUnacked();
}

void QuicConnection::MaybeSendInResponseToPacket() {
  if (!connected_) {
    return;
  }
  // Now that we have received an ack, we might be able to send packets which
  // are queued locally, or drain streams which are blocked.
  if (defer_send_in_response_to_packets_) {
    send_alarm_->Cancel();
    send_alarm_->Set(clock_->ApproximateNow());
  } else {
    WriteAndBundleAcksIfNotBlocked();
  }
}

void QuicConnection::SendVersionNegotiationPacket() {
  // TODO(alyssar): implement zero server state negotiation.
  pending_version_negotiation_packet_ = true;
  if (writer_->IsWriteBlocked()) {
    visitor_->OnWriteBlocked();
    return;
  }
  DVLOG(1) << ENDPOINT << "Sending version negotiation packet: {"
           << QuicVersionVectorToString(framer_.supported_versions()) << "}";
  std::unique_ptr<QuicEncryptedPacket> version_packet(
      packet_generator_.SerializeVersionNegotiationPacket(
          framer_.supported_versions()));
  WriteResult result = writer_->WritePacket(
      version_packet->data(), version_packet->length(),
      self_address().address(), peer_address(), per_packet_options_);

  if (result.status == WRITE_STATUS_ERROR) {
    OnWriteError(result.error_code);
    return;
  }
  if (result.status == WRITE_STATUS_BLOCKED) {
    visitor_->OnWriteBlocked();
    if (writer_->IsWriteBlockedDataBuffered()) {
      pending_version_negotiation_packet_ = false;
    }
    return;
  }

  pending_version_negotiation_packet_ = false;
}

QuicConsumedData QuicConnection::SendStreamData(
    QuicStreamId id,
    QuicIOVector iov,
    QuicStreamOffset offset,
    bool fin,
    QuicAckListenerInterface* listener) {
  if (!fin && iov.total_length == 0) {
    QUIC_BUG << "Attempt to send empty stream frame";
    return QuicConsumedData(0, false);
  }

  // Opportunistically bundle an ack with every outgoing packet.
  // Particularly, we want to bundle with handshake packets since we don't know
  // which decrypter will be used on an ack packet following a handshake
  // packet (a handshake packet from client to server could result in a REJ or a
  // SHLO from the server, leading to two different decrypters at the server.)
  //
  // TODO(jri): Note that ConsumeData may cause a response packet to be sent.
  // We may end up sending stale ack information if there are undecryptable
  // packets hanging around and/or there are revivable packets which may get
  // handled after this packet is sent. Change ScopedPacketBundler to do the
  // right thing: check ack_queued_, and then check undecryptable packets and
  // also if there is possibility of revival. Only bundle an ack if there's no
  // processing left that may cause received_info_ to change.
  ScopedRetransmissionScheduler alarm_delayer(this);
  ScopedPacketBundler ack_bundler(this, SEND_ACK_IF_PENDING);
  return packet_generator_.ConsumeData(id, iov, offset, fin, listener);
}

void QuicConnection::SendRstStream(QuicStreamId id,
                                   QuicRstStreamErrorCode error,
                                   QuicStreamOffset bytes_written) {
  // Opportunistically bundle an ack with this outgoing packet.
  ScopedPacketBundler ack_bundler(this, SEND_ACK_IF_PENDING);
  packet_generator_.AddControlFrame(QuicFrame(new QuicRstStreamFrame(
      id, AdjustErrorForVersion(error, version()), bytes_written)));

  if (error == QUIC_STREAM_NO_ERROR && version() > QUIC_VERSION_28) {
    // All data for streams which are reset with QUIC_STREAM_NO_ERROR must
    // be received by the peer.
    return;
  }

  sent_packet_manager_.CancelRetransmissionsForStream(id);
  // Remove all queued packets which only contain data for the reset stream.
  QueuedPacketList::iterator packet_iterator = queued_packets_.begin();
  while (packet_iterator != queued_packets_.end()) {
    QuicFrames* retransmittable_frames =
        &packet_iterator->retransmittable_frames;
    if (retransmittable_frames->empty()) {
      ++packet_iterator;
      continue;
    }
    QuicUtils::RemoveFramesForStream(retransmittable_frames, id);
    if (!retransmittable_frames->empty()) {
      ++packet_iterator;
      continue;
    }
    delete[] packet_iterator->encrypted_buffer;
    QuicUtils::ClearSerializedPacket(&(*packet_iterator));
    packet_iterator = queued_packets_.erase(packet_iterator);
  }
}

void QuicConnection::SendWindowUpdate(QuicStreamId id,
                                      QuicStreamOffset byte_offset) {
  // Opportunistically bundle an ack with this outgoing packet.
  ScopedPacketBundler ack_bundler(this, SEND_ACK_IF_PENDING);
  packet_generator_.AddControlFrame(
      QuicFrame(new QuicWindowUpdateFrame(id, byte_offset)));
}

void QuicConnection::SendBlocked(QuicStreamId id) {
  // Opportunistically bundle an ack with this outgoing packet.
  ScopedPacketBundler ack_bundler(this, SEND_ACK_IF_PENDING);
  packet_generator_.AddControlFrame(QuicFrame(new QuicBlockedFrame(id)));
}

void QuicConnection::SendPathClose(QuicPathId path_id) {
  // Opportunistically bundle an ack with this outgoing packet.
  ScopedPacketBundler ack_bundler(this, SEND_ACK_IF_PENDING);
  packet_generator_.AddControlFrame(QuicFrame(new QuicPathCloseFrame(path_id)));
  OnPathClosed(path_id);
}

const QuicConnectionStats& QuicConnection::GetStats() {
  const RttStats* rtt_stats = sent_packet_manager_.GetRttStats();

  // Update rtt and estimated bandwidth.
  QuicTime::Delta min_rtt = rtt_stats->min_rtt();
  if (min_rtt.IsZero()) {
    // If min RTT has not been set, use initial RTT instead.
    min_rtt = QuicTime::Delta::FromMicroseconds(rtt_stats->initial_rtt_us());
  }
  stats_.min_rtt_us = min_rtt.ToMicroseconds();

  QuicTime::Delta srtt = rtt_stats->smoothed_rtt();
  if (srtt.IsZero()) {
    // If SRTT has not been set, use initial RTT instead.
    srtt = QuicTime::Delta::FromMicroseconds(rtt_stats->initial_rtt_us());
  }
  stats_.srtt_us = srtt.ToMicroseconds();

  stats_.estimated_bandwidth = sent_packet_manager_.BandwidthEstimate();
  stats_.max_packet_size = packet_generator_.GetCurrentMaxPacketLength();
  stats_.max_received_packet_size = largest_received_packet_size_;
  return stats_;
}

void QuicConnection::ProcessUdpPacket(const IPEndPoint& self_address,
                                      const IPEndPoint& peer_address,
                                      const QuicReceivedPacket& packet) {
  if (!connected_) {
    return;
  }
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPacketReceived(self_address, peer_address, packet);
  }
  last_size_ = packet.length();
  current_packet_data_ = packet.data();

  last_packet_destination_address_ = self_address;
  last_packet_source_address_ = peer_address;
  if (!IsInitializedIPEndPoint(self_address_)) {
    self_address_ = last_packet_destination_address_;
  }
  if (!IsInitializedIPEndPoint(peer_address_)) {
    peer_address_ = last_packet_source_address_;
  }

  stats_.bytes_received += packet.length();
  ++stats_.packets_received;

  if (FLAGS_quic_use_socket_timestamp) {
    time_of_last_received_packet_ = packet.receipt_time();
    DVLOG(1) << ENDPOINT << "time of last received packet: "
             << time_of_last_received_packet_.ToDebuggingValue();
  }

  ScopedRetransmissionScheduler alarm_delayer(this);
  if (!framer_.ProcessPacket(packet)) {
    // If we are unable to decrypt this packet, it might be
    // because the CHLO or SHLO packet was lost.
    if (framer_.error() == QUIC_DECRYPTION_FAILURE) {
      if (encryption_level_ != ENCRYPTION_FORWARD_SECURE &&
          undecryptable_packets_.size() < max_undecryptable_packets_) {
        QueueUndecryptablePacket(packet);
      } else if (debug_visitor_ != nullptr) {
        debug_visitor_->OnUndecryptablePacket();
      }
    }
    DVLOG(1) << ENDPOINT << "Unable to process packet.  Last packet processed: "
             << last_header_.packet_number;
    current_packet_data_ = nullptr;
    return;
  }

  ++stats_.packets_processed;
  if (active_peer_migration_type_ != NO_CHANGE &&
      sent_packet_manager_.largest_observed() >
          highest_packet_sent_before_peer_migration_) {
    OnPeerMigrationValidated();
  }
  MaybeProcessUndecryptablePackets();
  MaybeSendInResponseToPacket();
  SetPingAlarm();
  current_packet_data_ = nullptr;
}

void QuicConnection::OnCanWrite() {
  DCHECK(!writer_->IsWriteBlocked());

  WriteQueuedPackets();
  WritePendingRetransmissions();

  // Sending queued packets may have caused the socket to become write blocked,
  // or the congestion manager to prohibit sending.  If we've sent everything
  // we had queued and we're still not blocked, let the visitor know it can
  // write more.
  if (!CanWrite(HAS_RETRANSMITTABLE_DATA)) {
    return;
  }

  {
    ScopedPacketBundler bundler(this, SEND_ACK_IF_QUEUED);
    visitor_->OnCanWrite();
    visitor_->PostProcessAfterData();
  }

  // After the visitor writes, it may have caused the socket to become write
  // blocked or the congestion manager to prohibit sending, so check again.
  if (visitor_->WillingAndAbleToWrite() && !resume_writes_alarm_->IsSet() &&
      CanWrite(HAS_RETRANSMITTABLE_DATA)) {
    // We're not write blocked, but some stream didn't write out all of its
    // bytes. Register for 'immediate' resumption so we'll keep writing after
    // other connections and events have had a chance to use the thread.
    resume_writes_alarm_->Set(clock_->ApproximateNow());
  }
}

void QuicConnection::WriteIfNotBlocked() {
  if (!writer_->IsWriteBlocked()) {
    OnCanWrite();
  }
}

void QuicConnection::WriteAndBundleAcksIfNotBlocked() {
  if (!writer_->IsWriteBlocked()) {
    ScopedPacketBundler bundler(this, SEND_ACK_IF_QUEUED);
    OnCanWrite();
  }
}

bool QuicConnection::ProcessValidatedPacket(const QuicPacketHeader& header) {
  if (header.fec_flag) {
    // Drop any FEC packet.
    return false;
  }

  if (perspective_ == Perspective::IS_SERVER &&
      IsInitializedIPEndPoint(self_address_) &&
      IsInitializedIPEndPoint(last_packet_destination_address_) &&
      (!(self_address_ == last_packet_destination_address_))) {
    CloseConnection(QUIC_ERROR_MIGRATING_ADDRESS,
                    "Self address migration is not supported at the server.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  if (!Near(header.packet_number, last_header_.packet_number)) {
    DVLOG(1) << ENDPOINT << "Packet " << header.packet_number
             << " out of bounds.  Discarding";
    CloseConnection(QUIC_INVALID_PACKET_HEADER, "packet number out of bounds.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  if (version_negotiation_state_ != NEGOTIATED_VERSION) {
    if (perspective_ == Perspective::IS_SERVER) {
      if (!header.public_header.version_flag) {
        // Packets should have the version flag till version negotiation is
        // done.
        string error_details =
            StringPrintf("%s Packet %" PRIu64
                         " without version flag before version negotiated.",
                         ENDPOINT, header.packet_number);
        DLOG(WARNING) << error_details;
        CloseConnection(QUIC_INVALID_VERSION, error_details,
                        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
        return false;
      } else {
        DCHECK_EQ(1u, header.public_header.versions.size());
        DCHECK_EQ(header.public_header.versions[0], version());
        version_negotiation_state_ = NEGOTIATED_VERSION;
        visitor_->OnSuccessfulVersionNegotiation(version());
        if (debug_visitor_ != nullptr) {
          debug_visitor_->OnSuccessfulVersionNegotiation(version());
        }
      }
    } else {
      DCHECK(!header.public_header.version_flag);
      // If the client gets a packet without the version flag from the server
      // it should stop sending version since the version negotiation is done.
      packet_generator_.StopSendingVersion();
      version_negotiation_state_ = NEGOTIATED_VERSION;
      visitor_->OnSuccessfulVersionNegotiation(version());
      if (debug_visitor_ != nullptr) {
        debug_visitor_->OnSuccessfulVersionNegotiation(version());
      }
    }
  }

  DCHECK_EQ(NEGOTIATED_VERSION, version_negotiation_state_);

  if (!FLAGS_quic_use_socket_timestamp) {
    time_of_last_received_packet_ = clock_->Now();
    DVLOG(1) << ENDPOINT << "time of last received packet: "
             << time_of_last_received_packet_.ToDebuggingValue();
  }

  if (last_size_ > largest_received_packet_size_) {
    largest_received_packet_size_ = last_size_;
  }

  if (perspective_ == Perspective::IS_SERVER &&
      encryption_level_ == ENCRYPTION_NONE &&
      last_size_ > packet_generator_.GetCurrentMaxPacketLength()) {
    SetMaxPacketLength(last_size_);
  }
  return true;
}

void QuicConnection::WriteQueuedPackets() {
  DCHECK(!writer_->IsWriteBlocked());

  if (pending_version_negotiation_packet_) {
    SendVersionNegotiationPacket();
  }

  QueuedPacketList::iterator packet_iterator = queued_packets_.begin();
  while (packet_iterator != queued_packets_.end() &&
         WritePacket(&(*packet_iterator))) {
    delete[] packet_iterator->encrypted_buffer;
    QuicUtils::ClearSerializedPacket(&(*packet_iterator));
    packet_iterator = queued_packets_.erase(packet_iterator);
  }
}

void QuicConnection::WritePendingRetransmissions() {
  // Keep writing as long as there's a pending retransmission which can be
  // written.
  while (sent_packet_manager_.HasPendingRetransmissions()) {
    const PendingRetransmission pending =
        sent_packet_manager_.NextPendingRetransmission();
    if (!CanWrite(HAS_RETRANSMITTABLE_DATA)) {
      break;
    }

    // Re-packetize the frames with a new packet number for retransmission.
    // Retransmitted packets use the same packet number length as the
    // original.
    // Flush the packet generator before making a new packet.
    // TODO(ianswett): Implement ReserializeAllFrames as a separate path that
    // does not require the creator to be flushed.
    packet_generator_.FlushAllQueuedFrames();
    char buffer[kMaxPacketSize];
    packet_generator_.ReserializeAllFrames(pending, buffer, kMaxPacketSize);
  }
}

void QuicConnection::RetransmitUnackedPackets(
    TransmissionType retransmission_type) {
  sent_packet_manager_.RetransmitUnackedPackets(retransmission_type);

  WriteIfNotBlocked();
}

void QuicConnection::NeuterUnencryptedPackets() {
  sent_packet_manager_.NeuterUnencryptedPackets();
  // This may have changed the retransmission timer, so re-arm it.
  SetRetransmissionAlarm();
}

bool QuicConnection::ShouldGeneratePacket(
    HasRetransmittableData retransmittable,
    IsHandshake handshake) {
  // We should serialize handshake packets immediately to ensure that they
  // end up sent at the right encryption level.
  if (handshake == IS_HANDSHAKE) {
    return true;
  }

  return CanWrite(retransmittable);
}

bool QuicConnection::CanWrite(HasRetransmittableData retransmittable) {
  if (!connected_) {
    return false;
  }

  if (writer_->IsWriteBlocked()) {
    visitor_->OnWriteBlocked();
    return false;
  }

  // Allow acks to be sent immediately.
  // TODO(ianswett): Remove retransmittable from
  // SendAlgorithmInterface::TimeUntilSend.
  if (retransmittable == NO_RETRANSMITTABLE_DATA) {
    return true;
  }
  // If the send alarm is set, wait for it to fire.
  if (send_alarm_->IsSet()) {
    return false;
  }

  QuicTime now = clock_->Now();
  QuicTime::Delta delay =
      sent_packet_manager_.TimeUntilSend(now, retransmittable);
  if (delay.IsInfinite()) {
    send_alarm_->Cancel();
    return false;
  }

  // If the scheduler requires a delay, then we can not send this packet now.
  if (!delay.IsZero()) {
    send_alarm_->Update(now.Add(delay), QuicTime::Delta::FromMilliseconds(1));
    DVLOG(1) << ENDPOINT << "Delaying sending " << delay.ToMilliseconds()
             << "ms";
    return false;
  }
  return true;
}

bool QuicConnection::WritePacket(SerializedPacket* packet) {
  if (packet->packet_number < sent_packet_manager_.largest_sent_packet()) {
    QUIC_BUG << "Attempt to write packet:" << packet->packet_number
             << " after:" << sent_packet_manager_.largest_sent_packet();
    CloseConnection(QUIC_INTERNAL_ERROR, "Packet written out of order.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return true;
  }
  if (ShouldDiscardPacket(*packet)) {
    ++stats_.packets_discarded;
    return true;
  }
  // Termination packets are encrypted and saved, so don't exit early.
  const bool is_termination_packet = IsTerminationPacket(*packet);
  if (writer_->IsWriteBlocked() && !is_termination_packet) {
    return false;
  }

  QuicPacketNumber packet_number = packet->packet_number;
  DCHECK_LE(packet_number_of_last_sent_packet_, packet_number);
  packet_number_of_last_sent_packet_ = packet_number;

  QuicPacketLength encrypted_length = packet->encrypted_length;
  // Termination packets are eventually owned by TimeWaitListManager.
  // Others are deleted at the end of this call.
  if (is_termination_packet) {
    if (termination_packets_.get() == nullptr) {
      termination_packets_.reset(new std::vector<QuicEncryptedPacket*>);
    }
    // Copy the buffer so it's owned in the future.
    char* buffer_copy = QuicUtils::CopyBuffer(*packet);
    termination_packets_->push_back(
        new QuicEncryptedPacket(buffer_copy, encrypted_length, true));
    // This assures we won't try to write *forced* packets when blocked.
    // Return true to stop processing.
    if (writer_->IsWriteBlocked()) {
      visitor_->OnWriteBlocked();
      return true;
    }
  }

  DCHECK_LE(encrypted_length, kMaxPacketSize);
  DCHECK_LE(encrypted_length, packet_generator_.GetCurrentMaxPacketLength());
  DVLOG(1) << ENDPOINT << "Sending packet " << packet_number << " : "
           << (IsRetransmittable(*packet) == HAS_RETRANSMITTABLE_DATA
                   ? "data bearing "
                   : " ack only ")
           << ", encryption level: "
           << QuicUtils::EncryptionLevelToString(packet->encryption_level)
           << ", encrypted length:" << encrypted_length;
  DVLOG(2) << ENDPOINT << "packet(" << packet_number << "): " << std::endl
           << QuicUtils::StringToHexASCIIDump(
                  StringPiece(packet->encrypted_buffer, encrypted_length));

  // Measure the RTT from before the write begins to avoid underestimating the
  // min_rtt_, especially in cases where the thread blocks or gets swapped out
  // during the WritePacket below.
  QuicTime packet_send_time = clock_->Now();
  WriteResult result = writer_->WritePacket(
      packet->encrypted_buffer, encrypted_length, self_address().address(),
      peer_address(), per_packet_options_);
  if (result.error_code == ERR_IO_PENDING) {
    DCHECK_EQ(WRITE_STATUS_BLOCKED, result.status);
  }

  if (result.status == WRITE_STATUS_BLOCKED) {
    visitor_->OnWriteBlocked();
    // If the socket buffers the the data, then the packet should not
    // be queued and sent again, which would result in an unnecessary
    // duplicate packet being sent.  The helper must call OnCanWrite
    // when the write completes, and OnWriteError if an error occurs.
    if (!writer_->IsWriteBlockedDataBuffered()) {
      return false;
    }
  }
  if (result.status != WRITE_STATUS_ERROR && debug_visitor_ != nullptr) {
    // Pass the write result to the visitor.
    debug_visitor_->OnPacketSent(*packet, packet->original_packet_number,
                                 packet->transmission_type, packet_send_time);
  }
  if (packet->transmission_type == NOT_RETRANSMISSION) {
    time_of_last_sent_new_packet_ = packet_send_time;
    if (IsRetransmittable(*packet) == HAS_RETRANSMITTABLE_DATA &&
        last_send_for_timeout_ <= time_of_last_received_packet_) {
      last_send_for_timeout_ = packet_send_time;
    }
  }
  SetPingAlarm();
  MaybeSetMtuAlarm();
  DVLOG(1) << ENDPOINT << "time we began writing last sent packet: "
           << packet_send_time.ToDebuggingValue();

  // TODO(ianswett): Change the packet number length and other packet creator
  // options by a more explicit API than setting a struct value directly,
  // perhaps via the NetworkChangeVisitor.
  packet_generator_.UpdateSequenceNumberLength(
      sent_packet_manager_.least_packet_awaited_by_peer(),
      sent_packet_manager_.EstimateMaxPacketsInFlight(max_packet_length()));

  bool reset_retransmission_alarm = sent_packet_manager_.OnPacketSent(
      packet, packet->original_packet_number, packet_send_time,
      packet->transmission_type, IsRetransmittable(*packet));

  if (reset_retransmission_alarm || !retransmission_alarm_->IsSet()) {
    SetRetransmissionAlarm();
  }

  stats_.bytes_sent += result.bytes_written;
  ++stats_.packets_sent;
  if (packet->transmission_type != NOT_RETRANSMISSION) {
    stats_.bytes_retransmitted += result.bytes_written;
    ++stats_.packets_retransmitted;
  }

  if (result.status == WRITE_STATUS_ERROR) {
    OnWriteError(result.error_code);
    DLOG(ERROR) << ENDPOINT << "failed writing " << encrypted_length
                << " bytes "
                << " from host " << (self_address().address().empty()
                                         ? " empty address "
                                         : self_address().ToStringWithoutPort())
                << " to address " << peer_address().ToString();
    return false;
  }

  return true;
}

bool QuicConnection::ShouldDiscardPacket(const SerializedPacket& packet) {
  if (!connected_) {
    DVLOG(1) << ENDPOINT << "Not sending packet as connection is disconnected.";
    return true;
  }

  QuicPacketNumber packet_number = packet.packet_number;
  if (encryption_level_ == ENCRYPTION_FORWARD_SECURE &&
      packet.encryption_level == ENCRYPTION_NONE) {
    // Drop packets that are NULL encrypted since the peer won't accept them
    // anymore.
    DVLOG(1) << ENDPOINT << "Dropping NULL encrypted packet: " << packet_number
             << " since the connection is forward secure.";
    return true;
  }

  // If a retransmission has been acked before sending, don't send it.
  // This occurs if a packet gets serialized, queued, then discarded.
  if (packet.transmission_type != NOT_RETRANSMISSION &&
      (!sent_packet_manager_.IsUnacked(packet.original_packet_number) ||
       !sent_packet_manager_.HasRetransmittableFrames(
           packet.original_packet_number))) {
    DVLOG(1) << ENDPOINT << "Dropping unacked packet: " << packet_number
             << " A previous transmission was acked while write blocked.";
    return true;
  }

  return false;
}

void QuicConnection::OnWriteError(int error_code) {
  const string error_details = "Write failed with error: " +
                               base::IntToString(error_code) + " (" +
                               ErrorToString(error_code) + ")";
  DVLOG(1) << ENDPOINT << error_details;
  // We can't send an error as the socket is presumably borked.
  TearDownLocalConnectionState(QUIC_PACKET_WRITE_ERROR, error_details,
                               ConnectionCloseSource::FROM_SELF);
}

void QuicConnection::OnSerializedPacket(SerializedPacket* serialized_packet) {
  DCHECK_NE(kInvalidPathId, serialized_packet->path_id);
  if (serialized_packet->encrypted_buffer == nullptr) {
    // We failed to serialize the packet, so close the connection.
    // TearDownLocalConnectionState does not send close packet, so no infinite
    // loop here.
    // TODO(ianswett): This is actually an internal error, not an
    // encryption failure.
    TearDownLocalConnectionState(
        QUIC_ENCRYPTION_FAILURE,
        "Serialized packet does not have an encrypted buffer.",
        ConnectionCloseSource::FROM_SELF);
    return;
  }
  SendOrQueuePacket(serialized_packet);
}

void QuicConnection::OnUnrecoverableError(QuicErrorCode error,
                                          const string& error_details,
                                          ConnectionCloseSource source) {
  // The packet creator or generator encountered an unrecoverable error: tear
  // down local connection state immediately.
  TearDownLocalConnectionState(error, error_details, source);
}

void QuicConnection::OnCongestionWindowChange() {
  visitor_->OnCongestionWindowChange(clock_->ApproximateNow());
}

void QuicConnection::OnRttChange() {
  // Uses the connection's smoothed RTT. If zero, uses initial_rtt.
  QuicTime::Delta rtt = sent_packet_manager_.GetRttStats()->smoothed_rtt();
  if (rtt.IsZero()) {
    rtt = QuicTime::Delta::FromMicroseconds(
        sent_packet_manager_.GetRttStats()->initial_rtt_us());
  }

  if (debug_visitor_)
    debug_visitor_->OnRttChanged(rtt);
}

void QuicConnection::OnPathDegrading() {
  visitor_->OnPathDegrading();
}

void QuicConnection::OnHandshakeComplete() {
  sent_packet_manager_.SetHandshakeConfirmed();
  // The client should immediately ack the SHLO to confirm the handshake is
  // complete with the server.
  if (perspective_ == Perspective::IS_CLIENT && !ack_queued_ &&
      ack_frame_updated()) {
    ack_alarm_->Cancel();
    ack_alarm_->Set(clock_->ApproximateNow());
  }
}

void QuicConnection::SendOrQueuePacket(SerializedPacket* packet) {
  // The caller of this function is responsible for checking CanWrite().
  if (packet->encrypted_buffer == nullptr) {
    QUIC_BUG << "packet.encrypted_buffer == nullptr in to SendOrQueuePacket";
    return;
  }

  sent_entropy_manager_.RecordPacketEntropyHash(packet->packet_number,
                                                packet->entropy_hash);
  // If there are already queued packets, queue this one immediately to ensure
  // it's written in sequence number order.
  if (!queued_packets_.empty() || !WritePacket(packet)) {
    // Take ownership of the underlying encrypted packet.
    packet->encrypted_buffer = QuicUtils::CopyBuffer(*packet);
    queued_packets_.push_back(*packet);
    packet->retransmittable_frames.clear();
  }

  QuicUtils::ClearSerializedPacket(packet);
  // If a forward-secure encrypter is available but is not being used and the
  // next packet number is the first packet which requires
  // forward security, start using the forward-secure encrypter.
  if (encryption_level_ != ENCRYPTION_FORWARD_SECURE &&
      has_forward_secure_encrypter_ &&
      packet->packet_number >= first_required_forward_secure_packet_ - 1) {
    SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  }
}

void QuicConnection::OnPingTimeout() {
  if (!retransmission_alarm_->IsSet()) {
    SendPing();
  }
}

void QuicConnection::SendPing() {
  ScopedPacketBundler bundler(this, SEND_ACK_IF_QUEUED);
  packet_generator_.AddControlFrame(QuicFrame(QuicPingFrame()));
  // Send PING frame immediately, without checking for congestion window bounds.
  packet_generator_.FlushAllQueuedFrames();
}

void QuicConnection::SendAck() {
  ack_alarm_->Cancel();
  ack_queued_ = false;
  stop_waiting_count_ = 0;
  num_retransmittable_packets_received_since_last_ack_sent_ = 0;
  last_ack_had_missing_packets_ = received_packet_manager_.HasMissingPackets();
  num_packets_received_since_last_ack_sent_ = 0;

  packet_generator_.SetShouldSendAck(true);
}

void QuicConnection::OnRetransmissionTimeout() {
  if (FLAGS_quic_always_has_unacked_packets_on_timeout) {
    DCHECK(sent_packet_manager_.HasUnackedPackets());
  } else {
    if (!sent_packet_manager_.HasUnackedPackets()) {
      return;
    }
  }

  if (close_connection_after_five_rtos_ &&
      sent_packet_manager_.consecutive_rto_count() >= 4) {
    // Close on the 5th consecutive RTO, so after 4 previous RTOs have occurred.
    CloseConnection(QUIC_TOO_MANY_RTOS, "5 consecutive retransmission timeouts",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  sent_packet_manager_.OnRetransmissionTimeout();
  WriteIfNotBlocked();

  // A write failure can result in the connection being closed, don't attempt to
  // write further packets, or to set alarms.
  if (!connected_) {
    return;
  }

  // In the TLP case, the SentPacketManager gives the connection the opportunity
  // to send new data before retransmitting.
  if (sent_packet_manager_.MaybeRetransmitTailLossProbe()) {
    // Send the pending retransmission now that it's been queued.
    WriteIfNotBlocked();
  }

  // Ensure the retransmission alarm is always set if there are unacked packets
  // and nothing waiting to be sent.
  // This happens if the loss algorithm invokes a timer based loss, but the
  // packet doesn't need to be retransmitted.
  if (!HasQueuedData() && !retransmission_alarm_->IsSet()) {
    SetRetransmissionAlarm();
  }
}

void QuicConnection::SetEncrypter(EncryptionLevel level,
                                  QuicEncrypter* encrypter) {
  packet_generator_.SetEncrypter(level, encrypter);
  if (level == ENCRYPTION_FORWARD_SECURE) {
    has_forward_secure_encrypter_ = true;
    first_required_forward_secure_packet_ =
        packet_number_of_last_sent_packet_ +
        // 3 times the current congestion window (in slow start) should cover
        // about two full round trips worth of packets, which should be
        // sufficient.
        3 *
            sent_packet_manager_.EstimateMaxPacketsInFlight(
                max_packet_length());
  }
}

void QuicConnection::SetDiversificationNonce(const DiversificationNonce nonce) {
  DCHECK_EQ(Perspective::IS_SERVER, perspective_);
  packet_generator_.SetDiversificationNonce(nonce);
}

void QuicConnection::SetDefaultEncryptionLevel(EncryptionLevel level) {
  encryption_level_ = level;
  packet_generator_.set_encryption_level(level);
}

void QuicConnection::SetDecrypter(EncryptionLevel level,
                                  QuicDecrypter* decrypter) {
  framer_.SetDecrypter(level, decrypter);
}

void QuicConnection::SetAlternativeDecrypter(EncryptionLevel level,
                                             QuicDecrypter* decrypter,
                                             bool latch_once_used) {
  framer_.SetAlternativeDecrypter(level, decrypter, latch_once_used);
}

const QuicDecrypter* QuicConnection::decrypter() const {
  return framer_.decrypter();
}

const QuicDecrypter* QuicConnection::alternative_decrypter() const {
  return framer_.alternative_decrypter();
}

void QuicConnection::QueueUndecryptablePacket(
    const QuicEncryptedPacket& packet) {
  DVLOG(1) << ENDPOINT << "Queueing undecryptable packet.";
  undecryptable_packets_.push_back(packet.Clone());
}

void QuicConnection::MaybeProcessUndecryptablePackets() {
  if (undecryptable_packets_.empty() || encryption_level_ == ENCRYPTION_NONE) {
    return;
  }

  while (connected_ && !undecryptable_packets_.empty()) {
    DVLOG(1) << ENDPOINT << "Attempting to process undecryptable packet";
    QuicEncryptedPacket* packet = undecryptable_packets_.front();
    if (!framer_.ProcessPacket(*packet) &&
        framer_.error() == QUIC_DECRYPTION_FAILURE) {
      DVLOG(1) << ENDPOINT << "Unable to process undecryptable packet...";
      break;
    }
    DVLOG(1) << ENDPOINT << "Processed undecryptable packet!";
    ++stats_.packets_processed;
    delete packet;
    undecryptable_packets_.pop_front();
  }

  // Once forward secure encryption is in use, there will be no
  // new keys installed and hence any undecryptable packets will
  // never be able to be decrypted.
  if (encryption_level_ == ENCRYPTION_FORWARD_SECURE) {
    if (debug_visitor_ != nullptr) {
      // TODO(rtenneti): perhaps more efficient to pass the number of
      // undecryptable packets as the argument to OnUndecryptablePacket so that
      // we just need to call OnUndecryptablePacket once?
      for (size_t i = 0; i < undecryptable_packets_.size(); ++i) {
        debug_visitor_->OnUndecryptablePacket();
      }
    }
    STLDeleteElements(&undecryptable_packets_);
  }
}

void QuicConnection::CloseConnection(
    QuicErrorCode error,
    const string& error_details,
    ConnectionCloseBehavior connection_close_behavior) {
  DCHECK(!error_details.empty());
  if (!connected_) {
    DVLOG(1) << "Connection is already closed.";
    return;
  }

  DVLOG(1) << ENDPOINT << "Closing connection: " << connection_id()
           << ", with error: " << QuicUtils::ErrorToString(error) << " ("
           << error << "), and details:  " << error_details;

  if (connection_close_behavior ==
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET) {
    SendConnectionClosePacket(error, error_details);
  }

  TearDownLocalConnectionState(error, error_details,
                               ConnectionCloseSource::FROM_SELF);
}

void QuicConnection::SendConnectionClosePacket(QuicErrorCode error,
                                               const string& details) {
  DVLOG(1) << ENDPOINT << "Sending connection close packet.";
  ClearQueuedPackets();
  ScopedPacketBundler ack_bundler(this, SEND_ACK);
  QuicConnectionCloseFrame* frame = new QuicConnectionCloseFrame();
  frame->error_code = error;
  frame->error_details = details;
  packet_generator_.AddControlFrame(QuicFrame(frame));
  packet_generator_.FlushAllQueuedFrames();
}

void QuicConnection::TearDownLocalConnectionState(
    QuicErrorCode error,
    const string& error_details,
    ConnectionCloseSource source) {
  if (!connected_) {
    DVLOG(1) << "Connection is already closed.";
    return;
  }
  connected_ = false;
  DCHECK(visitor_ != nullptr);
  // TODO(rtenneti): crbug.com/546668. A temporary fix. Added a check for null
  // |visitor_| to fix crash bug. Delete |visitor_| check and histogram after
  // fix is merged.
  if (visitor_ != nullptr) {
    visitor_->OnConnectionClosed(error, error_details, source);
  } else {
    UMA_HISTOGRAM_BOOLEAN("Net.QuicCloseConnection.NullVisitor", true);
  }
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnConnectionClosed(error, error_details, source);
  }
  // Cancel the alarms so they don't trigger any action now that the
  // connection is closed.
  ack_alarm_->Cancel();
  ping_alarm_->Cancel();
  resume_writes_alarm_->Cancel();
  retransmission_alarm_->Cancel();
  send_alarm_->Cancel();
  timeout_alarm_->Cancel();
  mtu_discovery_alarm_->Cancel();
}

void QuicConnection::SendGoAway(QuicErrorCode error,
                                QuicStreamId last_good_stream_id,
                                const string& reason) {
  if (goaway_sent_) {
    return;
  }
  goaway_sent_ = true;

  DVLOG(1) << ENDPOINT << "Going away with error "
           << QuicUtils::ErrorToString(error) << " (" << error << ")";

  // Opportunistically bundle an ack with this outgoing packet.
  ScopedPacketBundler ack_bundler(this, SEND_ACK_IF_PENDING);
  packet_generator_.AddControlFrame(
      QuicFrame(new QuicGoAwayFrame(error, last_good_stream_id, reason)));
}

QuicByteCount QuicConnection::max_packet_length() const {
  return packet_generator_.GetCurrentMaxPacketLength();
}

void QuicConnection::SetMaxPacketLength(QuicByteCount length) {
  return packet_generator_.SetMaxPacketLength(LimitMaxPacketSize(length));
}

bool QuicConnection::HasQueuedData() const {
  return pending_version_negotiation_packet_ || !queued_packets_.empty() ||
         packet_generator_.HasQueuedFrames();
}

void QuicConnection::EnableSavingCryptoPackets() {
  save_crypto_packets_as_termination_packets_ = true;
}

bool QuicConnection::CanWriteStreamData() {
  // Don't write stream data if there are negotiation or queued data packets
  // to send. Otherwise, continue and bundle as many frames as possible.
  if (pending_version_negotiation_packet_ || !queued_packets_.empty()) {
    return false;
  }

  IsHandshake pending_handshake =
      visitor_->HasPendingHandshake() ? IS_HANDSHAKE : NOT_HANDSHAKE;
  // Sending queued packets may have caused the socket to become write blocked,
  // or the congestion manager to prohibit sending.  If we've sent everything
  // we had queued and we're still not blocked, let the visitor know it can
  // write more.
  return ShouldGeneratePacket(HAS_RETRANSMITTABLE_DATA, pending_handshake);
}

void QuicConnection::SetNetworkTimeouts(QuicTime::Delta handshake_timeout,
                                        QuicTime::Delta idle_timeout) {
  QUIC_BUG_IF(idle_timeout > handshake_timeout)
      << "idle_timeout:" << idle_timeout.ToMilliseconds()
      << " handshake_timeout:" << handshake_timeout.ToMilliseconds();
  // Adjust the idle timeout on client and server to prevent clients from
  // sending requests to servers which have already closed the connection.
  if (perspective_ == Perspective::IS_SERVER) {
    idle_timeout = idle_timeout.Add(QuicTime::Delta::FromSeconds(3));
  } else if (idle_timeout > QuicTime::Delta::FromSeconds(1)) {
    idle_timeout = idle_timeout.Subtract(QuicTime::Delta::FromSeconds(1));
  }
  handshake_timeout_ = handshake_timeout;
  idle_network_timeout_ = idle_timeout;

  SetTimeoutAlarm();
}

void QuicConnection::CheckForTimeout() {
  QuicTime now = clock_->ApproximateNow();
  QuicTime time_of_last_packet =
      max(time_of_last_received_packet_, last_send_for_timeout_);

  // |delta| can be < 0 as |now| is approximate time but |time_of_last_packet|
  // is accurate time. However, this should not change the behavior of
  // timeout handling.
  QuicTime::Delta idle_duration = now.Subtract(time_of_last_packet);
  DVLOG(1) << ENDPOINT << "last packet "
           << time_of_last_packet.ToDebuggingValue()
           << " now:" << now.ToDebuggingValue()
           << " idle_duration:" << idle_duration.ToMicroseconds()
           << " idle_network_timeout: "
           << idle_network_timeout_.ToMicroseconds();
  if (idle_duration >= idle_network_timeout_) {
    const string error_details = "No recent network activity.";
    DVLOG(1) << ENDPOINT << error_details;
    CloseConnection(QUIC_NETWORK_IDLE_TIMEOUT, error_details,
                    idle_timeout_connection_close_behavior_);
    return;
  }

  if (!handshake_timeout_.IsInfinite()) {
    QuicTime::Delta connected_duration =
        now.Subtract(stats_.connection_creation_time);
    DVLOG(1) << ENDPOINT
             << "connection time: " << connected_duration.ToMicroseconds()
             << " handshake timeout: " << handshake_timeout_.ToMicroseconds();
    if (connected_duration >= handshake_timeout_) {
      const string error_details = "Handshake timeout expired.";
      DVLOG(1) << ENDPOINT << error_details;
      CloseConnection(QUIC_HANDSHAKE_TIMEOUT, error_details,
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return;
    }
  }

  SetTimeoutAlarm();
}

void QuicConnection::SetTimeoutAlarm() {
  QuicTime time_of_last_packet =
      max(time_of_last_received_packet_, time_of_last_sent_new_packet_);

  QuicTime deadline = time_of_last_packet.Add(idle_network_timeout_);
  if (!handshake_timeout_.IsInfinite()) {
    deadline =
        min(deadline, stats_.connection_creation_time.Add(handshake_timeout_));
  }

  timeout_alarm_->Cancel();
  timeout_alarm_->Set(deadline);
}

void QuicConnection::SetPingAlarm() {
  if (perspective_ == Perspective::IS_SERVER) {
    // Only clients send pings.
    return;
  }
  if (!visitor_->HasOpenDynamicStreams()) {
    ping_alarm_->Cancel();
    // Don't send a ping unless there are open streams.
    return;
  }
  QuicTime::Delta ping_timeout = QuicTime::Delta::FromSeconds(kPingTimeoutSecs);
  ping_alarm_->Update(clock_->ApproximateNow().Add(ping_timeout),
                      QuicTime::Delta::FromSeconds(1));
}

void QuicConnection::SetRetransmissionAlarm() {
  if (delay_setting_retransmission_alarm_) {
    pending_retransmission_alarm_ = true;
    return;
  }
  QuicTime retransmission_time = sent_packet_manager_.GetRetransmissionTime();
  retransmission_alarm_->Update(retransmission_time,
                                QuicTime::Delta::FromMilliseconds(1));
}

void QuicConnection::MaybeSetMtuAlarm() {
  // Do not set the alarm if the target size is less than the current size.
  // This covers the case when |mtu_discovery_target_| is at its default value,
  // zero.
  if (mtu_discovery_target_ <= max_packet_length()) {
    return;
  }

  if (mtu_probe_count_ >= kMtuDiscoveryAttempts) {
    return;
  }

  if (mtu_discovery_alarm_->IsSet()) {
    return;
  }

  if (packet_number_of_last_sent_packet_ >= next_mtu_probe_at_) {
    // Use an alarm to send the MTU probe to ensure that no ScopedPacketBundlers
    // are active.
    mtu_discovery_alarm_->Set(clock_->ApproximateNow());
  }
}

QuicConnection::ScopedPacketBundler::ScopedPacketBundler(
    QuicConnection* connection,
    AckBundling ack_mode)
    : connection_(connection),
      already_in_batch_mode_(connection != nullptr &&
                             connection->packet_generator_.InBatchMode()) {
  if (connection_ == nullptr) {
    return;
  }
  // Move generator into batch mode. If caller wants us to include an ack,
  // check the delayed-ack timer to see if there's ack info to be sent.
  if (!already_in_batch_mode_) {
    DVLOG(1) << "Entering Batch Mode.";
    connection_->packet_generator_.StartBatchOperations();
  }
  if (ShouldSendAck(ack_mode)) {
    DVLOG(1) << "Bundling ack with outgoing packet.";
    DCHECK(ack_mode == SEND_ACK || connection_->ack_frame_updated() ||
           connection_->stop_waiting_count_ > 1);
    connection_->SendAck();
  }
}

bool QuicConnection::ScopedPacketBundler::ShouldSendAck(
    AckBundling ack_mode) const {
  switch (ack_mode) {
    case SEND_ACK:
      return true;
    case SEND_ACK_IF_QUEUED:
      return connection_->ack_queued();
    case SEND_ACK_IF_PENDING:
      return connection_->ack_alarm_->IsSet() ||
             connection_->stop_waiting_count_ > 1;
    default:
      QUIC_BUG << "Unsupported ack_mode.";
      return true;
  }
}

QuicConnection::ScopedPacketBundler::~ScopedPacketBundler() {
  if (connection_ == nullptr) {
    return;
  }
  // If we changed the generator's batch state, restore original batch state.
  if (!already_in_batch_mode_) {
    DVLOG(1) << "Leaving Batch Mode.";
    connection_->packet_generator_.FinishBatchOperations();
  }
  DCHECK_EQ(already_in_batch_mode_,
            connection_->packet_generator_.InBatchMode());
}

QuicConnection::ScopedRetransmissionScheduler::ScopedRetransmissionScheduler(
    QuicConnection* connection)
    : connection_(connection),
      already_delayed_(connection_->delay_setting_retransmission_alarm_) {
  connection_->delay_setting_retransmission_alarm_ = true;
}

QuicConnection::ScopedRetransmissionScheduler::
    ~ScopedRetransmissionScheduler() {
  if (already_delayed_) {
    return;
  }
  connection_->delay_setting_retransmission_alarm_ = false;
  if (connection_->pending_retransmission_alarm_) {
    connection_->SetRetransmissionAlarm();
    connection_->pending_retransmission_alarm_ = false;
  }
}

HasRetransmittableData QuicConnection::IsRetransmittable(
    const SerializedPacket& packet) {
  // Retransmitted packets retransmittable frames are owned by the unacked
  // packet map, but are not present in the serialized packet.
  if (packet.transmission_type != NOT_RETRANSMISSION ||
      !packet.retransmittable_frames.empty()) {
    return HAS_RETRANSMITTABLE_DATA;
  } else {
    return NO_RETRANSMITTABLE_DATA;
  }
}

bool QuicConnection::IsTerminationPacket(const SerializedPacket& packet) {
  if (packet.retransmittable_frames.empty()) {
    return false;
  }
  for (const QuicFrame& frame : packet.retransmittable_frames) {
    if (frame.type == CONNECTION_CLOSE_FRAME) {
      return true;
    }
    if (save_crypto_packets_as_termination_packets_ &&
        frame.type == STREAM_FRAME &&
        frame.stream_frame->stream_id == kCryptoStreamId) {
      return true;
    }
  }
  return false;
}

void QuicConnection::SetMtuDiscoveryTarget(QuicByteCount target) {
  mtu_discovery_target_ = LimitMaxPacketSize(target);
}

QuicByteCount QuicConnection::LimitMaxPacketSize(
    QuicByteCount suggested_max_packet_size) {
  if (peer_address_.address().empty()) {
    QUIC_BUG << "Attempted to use a connection without a valid peer address";
    return suggested_max_packet_size;
  }

  const QuicByteCount writer_limit = writer_->GetMaxPacketSize(peer_address());

  QuicByteCount max_packet_size = suggested_max_packet_size;
  if (max_packet_size > writer_limit) {
    max_packet_size = writer_limit;
  }
  if (max_packet_size > kMaxPacketSize) {
    max_packet_size = kMaxPacketSize;
  }
  return max_packet_size;
}

void QuicConnection::SendMtuDiscoveryPacket(QuicByteCount target_mtu) {
  // Currently, this limit is ensured by the caller.
  DCHECK_EQ(target_mtu, LimitMaxPacketSize(target_mtu));

  // Create a listener for the new probe.  The ownership of the listener is
  // transferred to the AckNotifierManager.  The notifier will get destroyed
  // before the connection (because it's stored in one of the connection's
  // subfields), hence |this| pointer is guaranteed to stay valid at all times.
  scoped_refptr<MtuDiscoveryAckListener> last_mtu_discovery_ack_listener(
      new MtuDiscoveryAckListener(this, target_mtu));

  // Send the probe.
  packet_generator_.GenerateMtuDiscoveryPacket(
      target_mtu, last_mtu_discovery_ack_listener.get());
}

void QuicConnection::DiscoverMtu() {
  DCHECK(!mtu_discovery_alarm_->IsSet());

  // Chcek if the MTU has been already increased.
  if (mtu_discovery_target_ <= max_packet_length()) {
    return;
  }

  // Schedule the next probe *before* sending the current one.  This is
  // important, otherwise, when SendMtuDiscoveryPacket() is called,
  // MaybeSetMtuAlarm() will not realize that the probe has been just sent, and
  // will reschedule this probe again.
  packets_between_mtu_probes_ *= 2;
  next_mtu_probe_at_ =
      packet_number_of_last_sent_packet_ + packets_between_mtu_probes_ + 1;
  ++mtu_probe_count_;

  DVLOG(2) << "Sending a path MTU discovery packet #" << mtu_probe_count_;
  SendMtuDiscoveryPacket(mtu_discovery_target_);

  DCHECK(!mtu_discovery_alarm_->IsSet());
}

void QuicConnection::OnPeerMigrationValidated() {
  if (active_peer_migration_type_ == NO_CHANGE) {
    QUIC_BUG << "No migration underway.";
    return;
  }
  highest_packet_sent_before_peer_migration_ = 0;
  active_peer_migration_type_ = NO_CHANGE;
}

// TODO(jri): Modify method to start migration whenever a new IP address is seen
// from a packet with sequence number > the one that triggered the previous
// migration. This should happen even if a migration is underway, since the
// most recent migration is the one that we should pay attention to.
void QuicConnection::StartPeerMigration(
    PeerAddressChangeType peer_migration_type) {
  // TODO(fayang): Currently, all peer address change type are allowed. Need to
  // add a method ShouldAllowPeerAddressChange(PeerAddressChangeType type) to
  // determine whether |type| is allowed.
  if (active_peer_migration_type_ != NO_CHANGE ||
      peer_migration_type == NO_CHANGE) {
    QUIC_BUG << "Migration underway or no new migration started.";
    return;
  }
  DVLOG(1) << ENDPOINT << "Peer's ip:port changed from "
           << peer_address_.ToString() << " to "
           << last_packet_source_address_.ToString()
           << ", migrating connection.";

  highest_packet_sent_before_peer_migration_ =
      packet_number_of_last_sent_packet_;
  peer_address_ = last_packet_source_address_;
  active_peer_migration_type_ = peer_migration_type;

  // TODO(jri): Move these calls to OnPeerMigrationValidated. Rename
  // OnConnectionMigration methods to OnPeerMigration.
  visitor_->OnConnectionMigration(peer_migration_type);
  sent_packet_manager_.OnConnectionMigration(peer_migration_type);
}

void QuicConnection::OnPathClosed(QuicPathId path_id) {
  // Stop receiving packets on this path.
  framer_.OnPathClosed(path_id);
}

bool QuicConnection::ack_frame_updated() const {
  return received_packet_manager_.ack_frame_updated();
}

StringPiece QuicConnection::GetCurrentPacket() {
  if (current_packet_data_ == nullptr) {
    return StringPiece();
  }
  return StringPiece(current_packet_data_, last_size_);
}

}  // namespace net
