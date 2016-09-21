// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_session.h"

#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "net/quic/core/crypto/proof_verifier.h"
#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_flow_controller.h"
#if 0
#include "net/ssl/ssl_info.h"
#endif

using base::IntToString;
using base::StringPiece;
using std::make_pair;
using std::map;
using std::max;
using std::string;
using std::vector;
using net::SpdyPriority;

namespace net {

#define ENDPOINT \
  (perspective() == Perspective::IS_SERVER ? "Server: " : " Client: ")

QuicSession::QuicSession(QuicConnection* connection, const QuicConfig& config)
    : connection_(connection),
      config_(config),
      max_open_outgoing_streams_(kDefaultMaxStreamsPerConnection),
      max_open_incoming_streams_(config_.GetMaxIncomingDynamicStreamsToSend()),
      next_outgoing_stream_id_(perspective() == Perspective::IS_SERVER ? 2 : 3),
      largest_peer_created_stream_id_(
          perspective() == Perspective::IS_SERVER ? 1 : 0),
      num_dynamic_incoming_streams_(0),
      num_draining_incoming_streams_(0),
      num_locally_closed_incoming_streams_highest_offset_(0),
      error_(QUIC_NO_ERROR),
      flow_controller_(connection_,
                       0,
                       perspective(),
                       kMinimumFlowControlSendWindow,
                       config_.GetInitialSessionFlowControlWindowToSend(),
                       perspective() == Perspective::IS_SERVER),
      currently_writing_stream_id_(0) {}

void QuicSession::Initialize() {
  connection_->set_visitor(this);
  connection_->SetFromConfig(config_);

  DCHECK_EQ(kCryptoStreamId, GetCryptoStream()->id());
  static_stream_map_[kCryptoStreamId] = GetCryptoStream();
}

QuicSession::~QuicSession() {
  base::STLDeleteElements(&closed_streams_);
  base::STLDeleteValues(&dynamic_stream_map_);

  DLOG_IF(WARNING, num_locally_closed_incoming_streams_highest_offset() >
                       max_open_incoming_streams_)
      << "Surprisingly high number of locally closed peer initiated streams"
         "still waiting for final byte offset: "
      << num_locally_closed_incoming_streams_highest_offset();
  DLOG_IF(WARNING, GetNumLocallyClosedOutgoingStreamsHighestOffset() >
                       max_open_outgoing_streams_)
      << "Surprisingly high number of locally closed self initiated streams"
         "still waiting for final byte offset: "
      << GetNumLocallyClosedOutgoingStreamsHighestOffset();
}

void QuicSession::OnStreamFrame(const QuicStreamFrame& frame) {
  // TODO(rch) deal with the error case of stream id 0.
  QuicStreamId stream_id = frame.stream_id;
  ReliableQuicStream* stream = GetOrCreateStream(stream_id);
  if (!stream) {
    // The stream no longer exists, but we may still be interested in the
    // final stream byte offset sent by the peer. A frame with a FIN can give
    // us this offset.
    if (frame.fin) {
      QuicStreamOffset final_byte_offset = frame.offset + frame.data_length;
      UpdateFlowControlOnFinalReceivedByteOffset(stream_id, final_byte_offset);
    }
    return;
  }
  stream->OnStreamFrame(frame);
}

void QuicSession::OnRstStream(const QuicRstStreamFrame& frame) {
  if (base::ContainsKey(static_stream_map_, frame.stream_id)) {
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Attempt to reset a static stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  ReliableQuicStream* stream = GetOrCreateDynamicStream(frame.stream_id);
  if (!stream) {
    HandleRstOnValidNonexistentStream(frame);
    return;  // Errors are handled by GetOrCreateStream.
  }

  stream->OnStreamReset(frame);
}

void QuicSession::OnGoAway(const QuicGoAwayFrame& frame) {
  DCHECK(frame.last_good_stream_id < next_outgoing_stream_id_);
}

void QuicSession::OnConnectionClosed(QuicErrorCode error,
                                     const string& /*error_details*/,
                                     ConnectionCloseSource source) {
  DCHECK(!connection_->connected());
  if (error_ == QUIC_NO_ERROR) {
    error_ = error;
  }

  while (!dynamic_stream_map_.empty()) {
    DynamicStreamMap::iterator it = dynamic_stream_map_.begin();
    QuicStreamId id = it->first;
    it->second->OnConnectionClosed(error, source);
    // The stream should call CloseStream as part of OnConnectionClosed.
    if (dynamic_stream_map_.find(id) != dynamic_stream_map_.end()) {
      QUIC_BUG << ENDPOINT << "Stream failed to close under OnConnectionClosed";
      CloseStream(id);
    }
  }
}

void QuicSession::OnSuccessfulVersionNegotiation(
    const QuicVersion& /*version*/) {}

void QuicSession::OnPathDegrading() {}

void QuicSession::OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) {
  // Stream may be closed by the time we receive a WINDOW_UPDATE, so we can't
  // assume that it still exists.
  QuicStreamId stream_id = frame.stream_id;
  if (stream_id == kConnectionLevelId) {
    // This is a window update that applies to the connection, rather than an
    // individual stream.
    DVLOG(1) << ENDPOINT << "Received connection level flow control window "
                            "update with byte offset: "
             << frame.byte_offset;
    flow_controller_.UpdateSendWindowOffset(frame.byte_offset);
    return;
  }
  ReliableQuicStream* stream = GetOrCreateStream(stream_id);
  if (stream) {
    stream->OnWindowUpdateFrame(frame);
  }
}

void QuicSession::OnBlockedFrame(const QuicBlockedFrame& frame) {
  // TODO(rjshade): Compare our flow control receive windows for specified
  //                streams: if we have a large window then maybe something
  //                had gone wrong with the flow control accounting.
  DVLOG(1) << ENDPOINT
           << "Received BLOCKED frame with stream id: " << frame.stream_id;
}

void QuicSession::OnCanWrite() {
  // We limit the number of writes to the number of pending streams. If more
  // streams become pending, WillingAndAbleToWrite will be true, which will
  // cause the connection to request resumption before yielding to other
  // connections.
  size_t num_writes = write_blocked_streams_.NumBlockedStreams();
  if (flow_controller_.IsBlocked()) {
    // If we are connection level flow control blocked, then only allow the
    // crypto and headers streams to try writing as all other streams will be
    // blocked.
    num_writes = 0;
    if (write_blocked_streams_.crypto_stream_blocked()) {
      num_writes += 1;
    }
    if (write_blocked_streams_.headers_stream_blocked()) {
      num_writes += 1;
    }
  }
  if (num_writes == 0) {
    return;
  }

  QuicConnection::ScopedPacketBundler ack_bundler(
      connection_, QuicConnection::SEND_ACK_IF_QUEUED);
  for (size_t i = 0; i < num_writes; ++i) {
    if (!(write_blocked_streams_.HasWriteBlockedCryptoOrHeadersStream() ||
          write_blocked_streams_.HasWriteBlockedDataStreams())) {
      // Writing one stream removed another!? Something's broken.
      QUIC_BUG << "WriteBlockedStream is missing";
      connection_->CloseConnection(QUIC_INTERNAL_ERROR,
                                   "WriteBlockedStream is missing",
                                   ConnectionCloseBehavior::SILENT_CLOSE);
      return;
    }
    if (!connection_->CanWriteStreamData()) {
      return;
    }
    currently_writing_stream_id_ = write_blocked_streams_.PopFront();
    ReliableQuicStream* stream =
        GetOrCreateStream(currently_writing_stream_id_);
    if (stream != nullptr && !stream->flow_controller()->IsBlocked()) {
      // If the stream can't write all bytes it'll re-add itself to the blocked
      // list.
      stream->OnCanWrite();
    }
    currently_writing_stream_id_ = 0;
  }
}

bool QuicSession::WillingAndAbleToWrite() const {
  // If the crypto or headers streams are blocked, we want to schedule a write -
  // they don't get blocked by connection level flow control. Otherwise only
  // schedule a write if we are not flow control blocked at the connection
  // level.
  return write_blocked_streams_.HasWriteBlockedCryptoOrHeadersStream() ||
         (!flow_controller_.IsBlocked() &&
          write_blocked_streams_.HasWriteBlockedDataStreams());
}

bool QuicSession::HasPendingHandshake() const {
  return write_blocked_streams_.crypto_stream_blocked();
}

bool QuicSession::HasOpenDynamicStreams() const {
  return (dynamic_stream_map_.size() - draining_streams_.size() +
          locally_closed_streams_highest_offset_.size()) > 0;
}

void QuicSession::ProcessUdpPacket(const IPEndPoint& self_address,
                                   const IPEndPoint& peer_address,
                                   const QuicReceivedPacket& packet) {
  connection_->ProcessUdpPacket(self_address, peer_address, packet);
}

QuicConsumedData QuicSession::WritevData(
    ReliableQuicStream* stream,
    QuicStreamId id,
    QuicIOVector iov,
    QuicStreamOffset offset,
    bool fin,
    QuicAckListenerInterface* ack_notifier_delegate) {
  // This check is an attempt to deal with potential memory corruption
  // in which |id| ends up set to 1 (the crypto stream id). If this happen
  // it might end up resulting in unencrypted stream data being sent.
  // While this is impossible to avoid given sufficient corruption, this
  // seems like a reasonable mitigation.
  if (id == kCryptoStreamId && stream != GetCryptoStream()) {
    QUIC_BUG << "Stream id mismatch";
    connection_->CloseConnection(
        QUIC_INTERNAL_ERROR,
        "Non-crypto stream attempted to write data as crypto stream.",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return QuicConsumedData(0, false);
  }
  if (!IsEncryptionEstablished() && id != kCryptoStreamId) {
    // Do not let streams write without encryption. The calling stream will end
    // up write blocked until OnCanWrite is next called.
    return QuicConsumedData(0, false);
  }
  QuicConsumedData data =
      connection_->SendStreamData(id, iov, offset, fin, ack_notifier_delegate);
  write_blocked_streams_.UpdateBytesForStream(id, data.bytes_consumed);
  return data;
}

void QuicSession::SendRstStream(QuicStreamId id,
                                QuicRstStreamErrorCode error,
                                QuicStreamOffset bytes_written) {
  if (base::ContainsKey(static_stream_map_, id)) {
    QUIC_BUG << "Cannot send RST for a static stream with ID " << id;
    return;
  }

  if (connection()->connected()) {
    // Only send a RST_STREAM frame if still connected.
    connection_->SendRstStream(id, error, bytes_written);
  }
  CloseStreamInner(id, true);
}

void QuicSession::SendGoAway(QuicErrorCode error_code, const string& reason) {
  if (goaway_sent()) {
    return;
  }

  connection_->SendGoAway(error_code, largest_peer_created_stream_id_, reason);
}

void QuicSession::CloseStream(QuicStreamId stream_id) {
  CloseStreamInner(stream_id, false);
}

void QuicSession::InsertLocallyClosedStreamsHighestOffset(
    const QuicStreamId id,
    QuicStreamOffset offset) {
  locally_closed_streams_highest_offset_[id] = offset;
  if (IsIncomingStream(id)) {
    ++num_locally_closed_incoming_streams_highest_offset_;
  }
}

void QuicSession::CloseStreamInner(QuicStreamId stream_id, bool locally_reset) {
  DVLOG(1) << ENDPOINT << "Closing stream " << stream_id;

  DynamicStreamMap::iterator it = dynamic_stream_map_.find(stream_id);
  if (it == dynamic_stream_map_.end()) {
    // When CloseStreamInner has been called recursively (via
    // ReliableQuicStream::OnClose), the stream will already have been deleted
    // from stream_map_, so return immediately.
    DVLOG(1) << ENDPOINT << "Stream is already closed: " << stream_id;
    return;
  }
  ReliableQuicStream* stream = it->second;

  // Tell the stream that a RST has been sent.
  if (locally_reset) {
    stream->set_rst_sent(true);
  }

  closed_streams_.push_back(it->second);

  // If we haven't received a FIN or RST for this stream, we need to keep track
  // of the how many bytes the stream's flow controller believes it has
  // received, for accurate connection level flow control accounting.
  if (!stream->HasFinalReceivedByteOffset()) {
    InsertLocallyClosedStreamsHighestOffset(
        stream_id, stream->flow_controller()->highest_received_byte_offset());
  }

  dynamic_stream_map_.erase(it);
  if (IsIncomingStream(stream_id)) {
    --num_dynamic_incoming_streams_;
  }

  if (draining_streams_.find(stream_id) != draining_streams_.end() &&
      IsIncomingStream(stream_id)) {
    --num_draining_incoming_streams_;
  }
  draining_streams_.erase(stream_id);

  stream->OnClose();
  // Decrease the number of streams being emulated when a new one is opened.
  connection_->SetNumOpenStreams(dynamic_stream_map_.size());
}

void QuicSession::UpdateFlowControlOnFinalReceivedByteOffset(
    QuicStreamId stream_id,
    QuicStreamOffset final_byte_offset) {
  map<QuicStreamId, QuicStreamOffset>::iterator it =
      locally_closed_streams_highest_offset_.find(stream_id);
  if (it == locally_closed_streams_highest_offset_.end()) {
    return;
  }

  DVLOG(1) << ENDPOINT << "Received final byte offset " << final_byte_offset
           << " for stream " << stream_id;
  QuicByteCount offset_diff = final_byte_offset - it->second;
  if (flow_controller_.UpdateHighestReceivedOffset(
          flow_controller_.highest_received_byte_offset() + offset_diff)) {
    // If the final offset violates flow control, close the connection now.
    if (flow_controller_.FlowControlViolation()) {
      connection_->CloseConnection(
          QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA,
          "Connection level flow control violation",
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return;
    }
  }

  flow_controller_.AddBytesConsumed(offset_diff);
  locally_closed_streams_highest_offset_.erase(it);
  if (IsIncomingStream(stream_id)) {
    --num_locally_closed_incoming_streams_highest_offset_;
  }
}

bool QuicSession::IsEncryptionEstablished() {
  return GetCryptoStream()->encryption_established();
}

bool QuicSession::IsCryptoHandshakeConfirmed() {
  return GetCryptoStream()->handshake_confirmed();
}

void QuicSession::OnConfigNegotiated() {
  connection_->SetFromConfig(config_);

  const QuicVersion version = connection()->version();
  uint32_t max_streams = 0;
  if (version > QUIC_VERSION_34 &&
      config_.HasReceivedMaxIncomingDynamicStreams()) {
    max_streams = config_.ReceivedMaxIncomingDynamicStreams();
  } else {
    max_streams = config_.MaxStreamsPerConnection();
  }
  set_max_open_outgoing_streams(max_streams);

  if (version <= QUIC_VERSION_34) {
    // A small number of additional incoming streams beyond the limit should be
    // allowed. This helps avoid early connection termination when FIN/RSTs for
    // old streams are lost or arrive out of order.
    // Use a minimum number of additional streams, or a percentage increase,
    // whichever is larger.
    uint32_t max_incoming_streams =
        max(max_streams + kMaxStreamsMinimumIncrement,
            static_cast<uint32_t>(max_streams * kMaxStreamsMultiplier));
    set_max_open_incoming_streams(max_incoming_streams);
  } else {
    uint32_t max_incoming_streams_to_send =
        config_.GetMaxIncomingDynamicStreamsToSend();
    uint32_t max_incoming_streams =
        max(max_incoming_streams_to_send + kMaxStreamsMinimumIncrement,
            static_cast<uint32_t>(max_incoming_streams_to_send *
                                  kMaxStreamsMultiplier));
    set_max_open_incoming_streams(max_incoming_streams);
  }

  if (config_.HasReceivedInitialStreamFlowControlWindowBytes()) {
    // Streams which were created before the SHLO was received (0-RTT
    // requests) are now informed of the peer's initial flow control window.
    OnNewStreamFlowControlWindow(
        config_.ReceivedInitialStreamFlowControlWindowBytes());
  }
  if (config_.HasReceivedInitialSessionFlowControlWindowBytes()) {
    OnNewSessionFlowControlWindow(
        config_.ReceivedInitialSessionFlowControlWindowBytes());
  }
}

void QuicSession::HandleFrameOnNonexistentOutgoingStream(
    QuicStreamId stream_id) {
  DCHECK(!IsClosedStream(stream_id));
  // Received a frame for a locally-created stream that is not currently
  // active. This is an error.
  connection()->CloseConnection(
      QUIC_INVALID_STREAM_ID, "Data for nonexistent stream",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

void QuicSession::HandleRstOnValidNonexistentStream(
    const QuicRstStreamFrame& frame) {
  // If the stream is neither originally in active streams nor created in
  // GetOrCreateDynamicStream(), it could be a closed stream in which case its
  // final received byte offset need to be updated.
  if (IsClosedStream(frame.stream_id)) {
    // The RST frame contains the final byte offset for the stream: we can now
    // update the connection level flow controller if needed.
    UpdateFlowControlOnFinalReceivedByteOffset(frame.stream_id,
                                               frame.byte_offset);
  }
}

void QuicSession::OnNewStreamFlowControlWindow(QuicStreamOffset new_window) {
  if (new_window < kMinimumFlowControlSendWindow) {
    LOG(ERROR) << "Peer sent us an invalid stream flow control send window: "
               << new_window
               << ", below default: " << kMinimumFlowControlSendWindow;
    if (connection_->connected()) {
      connection_->CloseConnection(
          QUIC_FLOW_CONTROL_INVALID_WINDOW, "New stream window too low",
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    }
    return;
  }

  // Inform all existing streams about the new window.
  for (auto const& kv : static_stream_map_) {
    kv.second->UpdateSendWindowOffset(new_window);
  }
  for (auto const& kv : dynamic_stream_map_) {
    kv.second->UpdateSendWindowOffset(new_window);
  }
}

void QuicSession::OnNewSessionFlowControlWindow(QuicStreamOffset new_window) {
  if (new_window < kMinimumFlowControlSendWindow) {
    LOG(ERROR) << "Peer sent us an invalid session flow control send window: "
               << new_window
               << ", below default: " << kMinimumFlowControlSendWindow;
    if (connection_->connected()) {
      connection_->CloseConnection(
          QUIC_FLOW_CONTROL_INVALID_WINDOW, "New connection window too low",
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    }
    return;
  }

  flow_controller_.UpdateSendWindowOffset(new_window);
}

void QuicSession::OnCryptoHandshakeEvent(CryptoHandshakeEvent event) {
  switch (event) {
    // TODO(satyamshekhar): Move the logic of setting the encrypter/decrypter
    // to QuicSession since it is the glue.
    case ENCRYPTION_FIRST_ESTABLISHED:
      // Given any streams blocked by encryption a chance to write.
      OnCanWrite();
      break;

    case ENCRYPTION_REESTABLISHED:
      // Retransmit originally packets that were sent, since they can't be
      // decrypted by the peer.
      connection_->RetransmitUnackedPackets(ALL_INITIAL_RETRANSMISSION);
      // Given any streams blocked by encryption a chance to write.
      OnCanWrite();
      break;

    case HANDSHAKE_CONFIRMED:
      QUIC_BUG_IF(!config_.negotiated())
          << ENDPOINT << "Handshake confirmed without parameter negotiation.";
      // Discard originally encrypted packets, since they can't be decrypted by
      // the peer.
      connection_->NeuterUnencryptedPackets();
      break;

    default:
      LOG(ERROR) << ENDPOINT << "Got unknown handshake event: " << event;
  }
}

void QuicSession::OnCryptoHandshakeMessageSent(
    const CryptoHandshakeMessage& /*message*/) {}

void QuicSession::OnCryptoHandshakeMessageReceived(
    const CryptoHandshakeMessage& /*message*/) {}

QuicConfig* QuicSession::config() {
  return &config_;
}

void QuicSession::ActivateStream(ReliableQuicStream* stream) {
  DVLOG(1) << ENDPOINT << "num_streams: " << dynamic_stream_map_.size()
           << ". activating " << stream->id();
  DCHECK(!base::ContainsKey(dynamic_stream_map_, stream->id()));
  DCHECK(!base::ContainsKey(static_stream_map_, stream->id()));
  dynamic_stream_map_[stream->id()] = stream;
  if (IsIncomingStream(stream->id())) {
    ++num_dynamic_incoming_streams_;
  }
  // Increase the number of streams being emulated when a new one is opened.
  connection_->SetNumOpenStreams(dynamic_stream_map_.size());
}

QuicStreamId QuicSession::GetNextOutgoingStreamId() {
  QuicStreamId id = next_outgoing_stream_id_;
  next_outgoing_stream_id_ += 2;
  return id;
}

ReliableQuicStream* QuicSession::GetOrCreateStream(
    const QuicStreamId stream_id) {
  StaticStreamMap::iterator it = static_stream_map_.find(stream_id);
  if (it != static_stream_map_.end()) {
    return it->second;
  }
  return GetOrCreateDynamicStream(stream_id);
}

void QuicSession::StreamDraining(QuicStreamId stream_id) {
  DCHECK(base::ContainsKey(dynamic_stream_map_, stream_id));
  if (!base::ContainsKey(draining_streams_, stream_id)) {
    draining_streams_.insert(stream_id);
    if (IsIncomingStream(stream_id)) {
      ++num_draining_incoming_streams_;
    }
  }
}

bool QuicSession::MaybeIncreaseLargestPeerStreamId(
    const QuicStreamId stream_id) {
  if (stream_id <= largest_peer_created_stream_id_) {
    return true;
  }

  // Check if the new number of available streams would cause the number of
  // available streams to exceed the limit.  Note that the peer can create
  // only alternately-numbered streams.
  size_t additional_available_streams =
      (stream_id - largest_peer_created_stream_id_) / 2 - 1;
  size_t new_num_available_streams =
      GetNumAvailableStreams() + additional_available_streams;
  if (new_num_available_streams > MaxAvailableStreams()) {
    DVLOG(1) << "Failed to create a new incoming stream with id:" << stream_id
             << ".  There are already " << GetNumAvailableStreams()
             << " streams available, which would become "
             << new_num_available_streams << ", which exceeds the limit "
             << MaxAvailableStreams() << ".";
    string details = IntToString(new_num_available_streams) + " above " +
                     IntToString(MaxAvailableStreams());
    connection()->CloseConnection(
        QUIC_TOO_MANY_AVAILABLE_STREAMS, details.c_str(),
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  for (QuicStreamId id = largest_peer_created_stream_id_ + 2; id < stream_id;
       id += 2) {
    available_streams_.insert(id);
  }
  largest_peer_created_stream_id_ = stream_id;

  return true;
}

bool QuicSession::ShouldYield(QuicStreamId stream_id) {
  if (stream_id == currently_writing_stream_id_) {
    return false;
  }
  return write_blocked_streams()->ShouldYield(stream_id);
}

ReliableQuicStream* QuicSession::GetOrCreateDynamicStream(
    const QuicStreamId stream_id) {
  DCHECK(!base::ContainsKey(static_stream_map_, stream_id))
      << "Attempt to call GetOrCreateDynamicStream for a static stream";

  DynamicStreamMap::iterator it = dynamic_stream_map_.find(stream_id);
  if (it != dynamic_stream_map_.end()) {
    return it->second;
  }

  if (IsClosedStream(stream_id)) {
    return nullptr;
  }

  if (!IsIncomingStream(stream_id)) {
    HandleFrameOnNonexistentOutgoingStream(stream_id);
    return nullptr;
  }

  available_streams_.erase(stream_id);

  if (!MaybeIncreaseLargestPeerStreamId(stream_id)) {
    return nullptr;
  }
  // Check if the new number of open streams would cause the number of
  // open streams to exceed the limit.
  if (GetNumOpenIncomingStreams() >= max_open_incoming_streams()) {
    // Refuse to open the stream.
    SendRstStream(stream_id, QUIC_REFUSED_STREAM, 0);
    return nullptr;
  }

  return CreateIncomingDynamicStream(stream_id);
}

void QuicSession::set_max_open_incoming_streams(
    size_t max_open_incoming_streams) {
  DVLOG(1) << "Setting max_open_incoming_streams_ to "
           << max_open_incoming_streams;
  max_open_incoming_streams_ = max_open_incoming_streams;
  DVLOG(1) << "MaxAvailableStreams() became " << MaxAvailableStreams();
}

void QuicSession::set_max_open_outgoing_streams(
    size_t max_open_outgoing_streams) {
  DVLOG(1) << "Setting max_open_outgoing_streams_ to "
           << max_open_outgoing_streams;
  max_open_outgoing_streams_ = max_open_outgoing_streams;
}

bool QuicSession::goaway_sent() const {
  return connection_->goaway_sent();
}

bool QuicSession::goaway_received() const {
  return connection_->goaway_received();
}

bool QuicSession::IsClosedStream(QuicStreamId id) {
  DCHECK_NE(0u, id);
  if (IsOpenStream(id)) {
    // Stream is active
    return false;
  }
  if (!IsIncomingStream(id)) {
    // Locally created streams are strictly in-order.  If the id is in the
    // range of created streams and it's not active, it must have been closed.
    return id < next_outgoing_stream_id_;
  }
  // For peer created streams, we also need to consider available streams.
  return id <= largest_peer_created_stream_id_ &&
         !base::ContainsKey(available_streams_, id);
}

bool QuicSession::IsOpenStream(QuicStreamId id) {
  DCHECK_NE(0u, id);
  if (base::ContainsKey(static_stream_map_, id) ||
      base::ContainsKey(dynamic_stream_map_, id)) {
    // Stream is active
    return true;
  }
  return false;
}

size_t QuicSession::GetNumOpenIncomingStreams() const {
  return num_dynamic_incoming_streams_ - num_draining_incoming_streams_ +
         num_locally_closed_incoming_streams_highest_offset_;
}

size_t QuicSession::GetNumOpenOutgoingStreams() const {
  return GetNumDynamicOutgoingStreams() - GetNumDrainingOutgoingStreams() +
         GetNumLocallyClosedOutgoingStreamsHighestOffset();
}

size_t QuicSession::GetNumActiveStreams() const {
  return dynamic_stream_map_.size() - draining_streams_.size();
}

size_t QuicSession::GetNumAvailableStreams() const {
  return available_streams_.size();
}

void QuicSession::MarkConnectionLevelWriteBlocked(QuicStreamId id) {
  QUIC_BUG_IF(GetOrCreateStream(id) == nullptr) << "Marking unknown stream "
                                                << id << " blocked.";

  write_blocked_streams_.AddStream(id);
}

bool QuicSession::HasDataToWrite() const {
  return write_blocked_streams_.HasWriteBlockedCryptoOrHeadersStream() ||
         write_blocked_streams_.HasWriteBlockedDataStreams() ||
         connection_->HasQueuedData();
}

void QuicSession::PostProcessAfterData() {
  base::STLDeleteElements(&closed_streams_);
  closed_streams_.clear();
}

size_t QuicSession::GetNumDynamicOutgoingStreams() const {
  return dynamic_stream_map_.size() - num_dynamic_incoming_streams_;
}

size_t QuicSession::GetNumDrainingOutgoingStreams() const {
  return draining_streams_.size() - num_draining_incoming_streams_;
}

size_t QuicSession::GetNumLocallyClosedOutgoingStreamsHighestOffset() const {
  return locally_closed_streams_highest_offset_.size() -
         num_locally_closed_incoming_streams_highest_offset_;
}

bool QuicSession::IsConnectionFlowControlBlocked() const {
  return flow_controller_.IsBlocked();
}

bool QuicSession::IsStreamFlowControlBlocked() {
  for (auto const& kv : static_stream_map_) {
    if (kv.second->flow_controller()->IsBlocked()) {
      return true;
    }
  }
  for (auto const& kv : dynamic_stream_map_) {
    if (kv.second->flow_controller()->IsBlocked()) {
      return true;
    }
  }
  return false;
}

size_t QuicSession::MaxAvailableStreams() const {
  return max_open_incoming_streams_ * kMaxAvailableStreamsMultiplier;
}

bool QuicSession::IsIncomingStream(QuicStreamId id) const {
  return id % 2 != next_outgoing_stream_id_ % 2;
}

}  // namespace net
