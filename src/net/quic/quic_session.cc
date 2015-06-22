// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_session.h"

#include "base/stl_util.h"
#include "net/quic/crypto/proof_verifier.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_flow_controller.h"
#if 0
#include "net/ssl/ssl_info.h"
#endif

using base::StringPiece;
using base::hash_map;
using base::hash_set;
using std::make_pair;
using std::map;
using std::max;
using std::string;
using std::vector;

namespace net {

#define ENDPOINT \
  (perspective() == Perspective::IS_SERVER ? "Server: " : " Client: ")

// We want to make sure we delete any closed streams in a safe manner.
// To avoid deleting a stream in mid-operation, we have a simple shim between
// us and the stream, so we can delete any streams when we return from
// processing.
//
// We could just override the base methods, but this makes it easier to make
// sure we don't miss any.
class VisitorShim : public QuicConnectionVisitorInterface {
 public:
  explicit VisitorShim(QuicSession* session) : session_(session) {}

  void OnStreamFrames(const vector<QuicStreamFrame>& frames) override {
    session_->OnStreamFrames(frames);
    session_->PostProcessAfterData();
  }
  void OnRstStream(const QuicRstStreamFrame& frame) override {
    session_->OnRstStream(frame);
    session_->PostProcessAfterData();
  }

  void OnGoAway(const QuicGoAwayFrame& frame) override {
    session_->OnGoAway(frame);
    session_->PostProcessAfterData();
  }

  void OnWindowUpdateFrames(
      const vector<QuicWindowUpdateFrame>& frames) override {
    session_->OnWindowUpdateFrames(frames);
    session_->PostProcessAfterData();
  }

  void OnBlockedFrames(const vector<QuicBlockedFrame>& frames) override {
    session_->OnBlockedFrames(frames);
    session_->PostProcessAfterData();
  }

  void OnCanWrite() override {
    session_->OnCanWrite();
    session_->PostProcessAfterData();
  }

  void OnCongestionWindowChange(QuicTime now) override {
    session_->OnCongestionWindowChange(now);
  }

  void OnSuccessfulVersionNegotiation(const QuicVersion& version) override {
    session_->OnSuccessfulVersionNegotiation(version);
  }

  void OnConnectionClosed(QuicErrorCode error, bool from_peer) override {
    session_->OnConnectionClosed(error, from_peer);
    // The session will go away, so don't bother with cleanup.
  }

  void OnWriteBlocked() override { session_->OnWriteBlocked(); }

  bool WillingAndAbleToWrite() const override {
    return session_->WillingAndAbleToWrite();
  }

  bool HasPendingHandshake() const override {
    return session_->HasPendingHandshake();
  }

  bool HasOpenDynamicStreams() const override {
    return session_->HasOpenDynamicStreams();
  }

 private:
  QuicSession* session_;
};

QuicSession::QuicSession(QuicConnection* connection, const QuicConfig& config)
    : connection_(connection),
      visitor_shim_(new VisitorShim(this)),
      config_(config),
      max_open_streams_(config_.MaxStreamsPerConnection()),
      next_stream_id_(perspective() == Perspective::IS_SERVER ? 2 : 3),
      largest_peer_created_stream_id_(
          perspective() == Perspective::IS_SERVER ? 1 : 0),
      error_(QUIC_NO_ERROR),
      flow_controller_(connection_.get(),
                       0,
                       perspective(),
                       kMinimumFlowControlSendWindow,
                       config_.GetInitialSessionFlowControlWindowToSend(),
                       false),
      goaway_received_(false),
      goaway_sent_(false),
      has_pending_handshake_(false) {
}

void QuicSession::Initialize() {
  connection_->set_visitor(visitor_shim_.get());
  connection_->SetFromConfig(config_);

  DCHECK_EQ(kCryptoStreamId, GetCryptoStream()->id());
  static_stream_map_[kCryptoStreamId] = GetCryptoStream();
}

QuicSession::~QuicSession() {
  STLDeleteElements(&closed_streams_);
  STLDeleteValues(&dynamic_stream_map_);

  DLOG_IF(WARNING,
          locally_closed_streams_highest_offset_.size() > max_open_streams_)
      << "Surprisingly high number of locally closed streams still waiting for "
         "final byte offset: " << locally_closed_streams_highest_offset_.size();
}

void QuicSession::OnStreamFrames(const vector<QuicStreamFrame>& frames) {
  for (size_t i = 0; i < frames.size() && connection_->connected(); ++i) {
    // TODO(rch) deal with the error case of stream id 0.
    const QuicStreamFrame& frame = frames[i];
    QuicStreamId stream_id = frame.stream_id;
    ReliableQuicStream* stream = GetStream(stream_id);
    if (!stream) {
      // The stream no longer exists, but we may still be interested in the
      // final stream byte offset sent by the peer. A frame with a FIN can give
      // us this offset.
      if (frame.fin) {
        QuicStreamOffset final_byte_offset = frame.offset + frame.data.size();
        UpdateFlowControlOnFinalReceivedByteOffset(stream_id,
                                                   final_byte_offset);
      }

      continue;
    }
    stream->OnStreamFrame(frames[i]);
  }
}

void QuicSession::OnRstStream(const QuicRstStreamFrame& frame) {
  if (ContainsKey(static_stream_map_, frame.stream_id)) {
    connection()->SendConnectionCloseWithDetails(
        QUIC_INVALID_STREAM_ID, "Attempt to reset a static stream");
    return;
  }

  ReliableQuicStream* stream = GetDynamicStream(frame.stream_id);
  if (!stream) {
    // The RST frame contains the final byte offset for the stream: we can now
    // update the connection level flow controller if needed.
    UpdateFlowControlOnFinalReceivedByteOffset(frame.stream_id,
                                               frame.byte_offset);
    return;  // Errors are handled by GetStream.
  }

  stream->OnStreamReset(frame);
}

void QuicSession::OnGoAway(const QuicGoAwayFrame& frame) {
  DCHECK(frame.last_good_stream_id < next_stream_id_);
  goaway_received_ = true;
}

void QuicSession::OnConnectionClosed(QuicErrorCode error, bool from_peer) {
  DCHECK(!connection_->connected());
  if (error_ == QUIC_NO_ERROR) {
    error_ = error;
  }

  while (!dynamic_stream_map_.empty()) {
    StreamMap::iterator it = dynamic_stream_map_.begin();
    QuicStreamId id = it->first;
    it->second->OnConnectionClosed(error, from_peer);
    // The stream should call CloseStream as part of OnConnectionClosed.
    if (dynamic_stream_map_.find(id) != dynamic_stream_map_.end()) {
      LOG(DFATAL) << ENDPOINT
                  << "Stream failed to close under OnConnectionClosed";
      CloseStream(id);
    }
  }
}

void QuicSession::OnSuccessfulVersionNegotiation(const QuicVersion& version) {
}

void QuicSession::OnWindowUpdateFrames(
    const vector<QuicWindowUpdateFrame>& frames) {
  bool connection_window_updated = false;
  for (size_t i = 0; i < frames.size(); ++i) {
    // Stream may be closed by the time we receive a WINDOW_UPDATE, so we can't
    // assume that it still exists.
    QuicStreamId stream_id = frames[i].stream_id;
    if (stream_id == kConnectionLevelId) {
      // This is a window update that applies to the connection, rather than an
      // individual stream.
      DVLOG(1) << ENDPOINT
               << "Received connection level flow control window update with "
                  "byte offset: " << frames[i].byte_offset;
      if (flow_controller_.UpdateSendWindowOffset(frames[i].byte_offset)) {
        connection_window_updated = true;
      }
      continue;
    }

    ReliableQuicStream* stream = GetStream(stream_id);
    if (stream) {
      stream->OnWindowUpdateFrame(frames[i]);
    }
  }

  // Connection level flow control window has increased, so blocked streams can
  // write again.
  if (connection_window_updated) {
    OnCanWrite();
  }
}

void QuicSession::OnBlockedFrames(const vector<QuicBlockedFrame>& frames) {
  for (size_t i = 0; i < frames.size(); ++i) {
    // TODO(rjshade): Compare our flow control receive windows for specified
    //                streams: if we have a large window then maybe something
    //                had gone wrong with the flow control accounting.
    DVLOG(1) << ENDPOINT << "Received BLOCKED frame with stream id: "
             << frames[i].stream_id;
  }
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
      connection_.get(), QuicConnection::NO_ACK);
  for (size_t i = 0; i < num_writes; ++i) {
    if (!(write_blocked_streams_.HasWriteBlockedCryptoOrHeadersStream() ||
          write_blocked_streams_.HasWriteBlockedDataStreams())) {
      // Writing one stream removed another!? Something's broken.
      LOG(DFATAL) << "WriteBlockedStream is missing";
      connection_->CloseConnection(QUIC_INTERNAL_ERROR, false);
      return;
    }
    if (!connection_->CanWriteStreamData()) {
      return;
    }
    QuicStreamId stream_id = write_blocked_streams_.PopFront();
    if (stream_id == kCryptoStreamId) {
      has_pending_handshake_ = false;  // We just popped it.
    }
    ReliableQuicStream* stream = GetStream(stream_id);
    if (stream != nullptr && !stream->flow_controller()->IsBlocked()) {
      // If the stream can't write all bytes, it'll re-add itself to the blocked
      // list.
      stream->OnCanWrite();
    }
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
  return has_pending_handshake_;
}

bool QuicSession::HasOpenDynamicStreams() const {
  return GetNumOpenStreams() > 0;
}

QuicConsumedData QuicSession::WritevData(
    QuicStreamId id,
    const QuicIOVector& iov,
    QuicStreamOffset offset,
    bool fin,
    FecProtection fec_protection,
    QuicAckNotifier::DelegateInterface* ack_notifier_delegate) {
  return connection_->SendStreamData(id, iov, offset, fin, fec_protection,
                                     ack_notifier_delegate);
}

void QuicSession::SendRstStream(QuicStreamId id,
                                QuicRstStreamErrorCode error,
                                QuicStreamOffset bytes_written) {
  if (ContainsKey(static_stream_map_, id)) {
    LOG(DFATAL) << "Cannot send RST for a static stream with ID " << id;
    return;
  }

  if (connection()->connected()) {
    // Only send a RST_STREAM frame if still connected.
    connection_->SendRstStream(id, error, bytes_written);
  }
  CloseStreamInner(id, true);
}

void QuicSession::SendGoAway(QuicErrorCode error_code, const string& reason) {
  if (goaway_sent_) {
    return;
  }
  goaway_sent_ = true;
  connection_->SendGoAway(error_code, largest_peer_created_stream_id_, reason);
}

void QuicSession::CloseStream(QuicStreamId stream_id) {
  CloseStreamInner(stream_id, false);
}

void QuicSession::CloseStreamInner(QuicStreamId stream_id,
                                   bool locally_reset) {
  DVLOG(1) << ENDPOINT << "Closing stream " << stream_id;

  StreamMap::iterator it = dynamic_stream_map_.find(stream_id);
  if (it == dynamic_stream_map_.end()) {
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
    locally_closed_streams_highest_offset_[stream_id] =
        stream->flow_controller()->highest_received_byte_offset();
  }

  dynamic_stream_map_.erase(it);
  stream->OnClose();
  // Decrease the number of streams being emulated when a new one is opened.
  connection_->SetNumOpenStreams(dynamic_stream_map_.size());
}

void QuicSession::UpdateFlowControlOnFinalReceivedByteOffset(
    QuicStreamId stream_id, QuicStreamOffset final_byte_offset) {
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
      connection_->SendConnectionClose(
          QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA);
      return;
    }
  }

  flow_controller_.AddBytesConsumed(offset_diff);
  locally_closed_streams_highest_offset_.erase(it);
}

bool QuicSession::IsEncryptionEstablished() {
  return GetCryptoStream()->encryption_established();
}

bool QuicSession::IsCryptoHandshakeConfirmed() {
  return GetCryptoStream()->handshake_confirmed();
}

void QuicSession::OnConfigNegotiated() {
  connection_->SetFromConfig(config_);

  uint32 max_streams = config_.MaxStreamsPerConnection();
  if (perspective() == Perspective::IS_SERVER) {
    // A server should accept a small number of additional streams beyond the
    // limit sent to the client. This helps avoid early connection termination
    // when FIN/RSTs for old streams are lost or arrive out of order.
    // Use a minimum number of additional streams, or a percentage increase,
    // whichever is larger.
    max_streams =
        max(max_streams + kMaxStreamsMinimumIncrement,
            static_cast<uint32>(max_streams * kMaxStreamsMultiplier));

    if (config_.HasReceivedConnectionOptions() &&
        ContainsQuicTag(config_.ReceivedConnectionOptions(), kAFCW)) {
      EnableAutoTuneReceiveWindow();
    }
  }
  set_max_open_streams(max_streams);

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

void QuicSession::EnableAutoTuneReceiveWindow() {
  flow_controller_.set_auto_tune_receive_window(true);
  // Inform all existing streams about the new window.
  for (auto const& kv : static_stream_map_) {
    kv.second->flow_controller()->set_auto_tune_receive_window(true);
  }
  for (auto const& kv : dynamic_stream_map_) {
    kv.second->flow_controller()->set_auto_tune_receive_window(true);
  }
}

void QuicSession::OnNewStreamFlowControlWindow(QuicStreamOffset new_window) {
  if (new_window < kMinimumFlowControlSendWindow) {
    LOG(ERROR) << "Peer sent us an invalid stream flow control send window: "
               << new_window
               << ", below default: " << kMinimumFlowControlSendWindow;
    if (connection_->connected()) {
      connection_->SendConnectionClose(QUIC_FLOW_CONTROL_INVALID_WINDOW);
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
      connection_->SendConnectionClose(QUIC_FLOW_CONTROL_INVALID_WINDOW);
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
      break;

    case ENCRYPTION_REESTABLISHED:
      // Retransmit originally packets that were sent, since they can't be
      // decrypted by the peer.
      connection_->RetransmitUnackedPackets(ALL_INITIAL_RETRANSMISSION);
      break;

    case HANDSHAKE_CONFIRMED:
      LOG_IF(DFATAL, !config_.negotiated()) << ENDPOINT
          << "Handshake confirmed without parameter negotiation.";
      // Discard originally encrypted packets, since they can't be decrypted by
      // the peer.
      connection_->NeuterUnencryptedPackets();
      break;

    default:
      LOG(ERROR) << ENDPOINT << "Got unknown handshake event: " << event;
  }
}

void QuicSession::OnCryptoHandshakeMessageSent(
    const CryptoHandshakeMessage& message) {
}

void QuicSession::OnCryptoHandshakeMessageReceived(
    const CryptoHandshakeMessage& message) {
}

QuicConfig* QuicSession::config() {
  return &config_;
}

void QuicSession::ActivateStream(ReliableQuicStream* stream) {
  DVLOG(1) << ENDPOINT << "num_streams: " << dynamic_stream_map_.size()
           << ". activating " << stream->id();
  DCHECK_EQ(dynamic_stream_map_.count(stream->id()), 0u);
  dynamic_stream_map_[stream->id()] = stream;
  // Increase the number of streams being emulated when a new one is opened.
  connection_->SetNumOpenStreams(dynamic_stream_map_.size());
}

QuicStreamId QuicSession::GetNextStreamId() {
  QuicStreamId id = next_stream_id_;
  next_stream_id_ += 2;
  return id;
}

ReliableQuicStream* QuicSession::GetStream(const QuicStreamId stream_id) {
  StreamMap::iterator it = static_stream_map_.find(stream_id);
  if (it != static_stream_map_.end()) {
    return it->second;
  }
  return GetDynamicStream(stream_id);
}

ReliableQuicStream* QuicSession::GetDynamicStream(
    const QuicStreamId stream_id) {
  if (static_stream_map_.find(stream_id) != static_stream_map_.end()) {
    DLOG(FATAL) << "Attempt to call GetDynamicStream for a static stream";
    return nullptr;
  }

  StreamMap::iterator it = dynamic_stream_map_.find(stream_id);
  if (it != dynamic_stream_map_.end()) {
    return it->second;
  }

  if (IsClosedStream(stream_id)) {
    return nullptr;
  }

  if (stream_id % 2 == next_stream_id_ % 2) {
    // We've received a frame for a locally-created stream that is not
    // currently active.  This is an error.
    if (connection()->connected()) {
      connection()->SendConnectionClose(QUIC_PACKET_FOR_NONEXISTENT_STREAM);
    }
    return nullptr;
  }

  return GetIncomingDynamicStream(stream_id);
}

ReliableQuicStream* QuicSession::GetIncomingDynamicStream(
    QuicStreamId stream_id) {
  if (IsClosedStream(stream_id)) {
    return nullptr;
  }

  implicitly_created_streams_.erase(stream_id);
  if (stream_id > largest_peer_created_stream_id_) {
    if (stream_id - largest_peer_created_stream_id_ > kMaxStreamIdDelta) {
      // We may already have sent a connection close due to multiple reset
      // streams in the same packet.
      if (connection()->connected()) {
        LOG(ERROR) << "Trying to get stream: " << stream_id
                   << ", largest peer created stream: "
                   << largest_peer_created_stream_id_
                   << ", max delta: " << kMaxStreamIdDelta;
        connection()->SendConnectionClose(QUIC_INVALID_STREAM_ID);
      }
      return nullptr;
    }
    for (QuicStreamId id = largest_peer_created_stream_id_ + 2;
         id < stream_id;
         id += 2) {
      implicitly_created_streams_.insert(id);
    }
    largest_peer_created_stream_id_ = stream_id;
  }
  ReliableQuicStream* stream = CreateIncomingDynamicStream(stream_id);
  if (stream == nullptr) {
    return nullptr;
  }
  ActivateStream(stream);
  return stream;
}

void QuicSession::set_max_open_streams(size_t max_open_streams) {
  DVLOG(1) << "Setting max_open_streams_ to " << max_open_streams;
  max_open_streams_ = max_open_streams;
}

bool QuicSession::IsClosedStream(QuicStreamId id) {
  DCHECK_NE(0u, id);
  if (ContainsKey(static_stream_map_, id) ||
      ContainsKey(dynamic_stream_map_, id)) {
    // Stream is active
    return false;
  }
  if (id % 2 == next_stream_id_ % 2) {
    // Locally created streams are strictly in-order.  If the id is in the
    // range of created streams and it's not active, it must have been closed.
    return id < next_stream_id_;
  }
  // For peer created streams, we also need to consider implicitly created
  // streams.
  return id <= largest_peer_created_stream_id_ &&
      !ContainsKey(implicitly_created_streams_, id);
}

size_t QuicSession::GetNumOpenStreams() const {
  return dynamic_stream_map_.size() + implicitly_created_streams_.size();
}

void QuicSession::MarkWriteBlocked(QuicStreamId id, QuicPriority priority) {
#ifndef NDEBUG
  ReliableQuicStream* stream = GetStream(id);
  if (stream != nullptr) {
    LOG_IF(DFATAL, priority != stream->EffectivePriority())
        << ENDPOINT << "Stream " << id
        << "Priorities do not match.  Got: " << priority
        << " Expected: " << stream->EffectivePriority();
  } else {
    LOG(DFATAL) << "Marking unknown stream " << id << " blocked.";
  }
#endif

  if (id == kCryptoStreamId) {
    DCHECK(!has_pending_handshake_);
    has_pending_handshake_ = true;
    // TODO(jar): Be sure to use the highest priority for the crypto stream,
    // perhaps by adding a "special" priority for it that is higher than
    // kHighestPriority.
    priority = kHighestPriority;
  }
  write_blocked_streams_.PushBack(id, priority);
}

bool QuicSession::HasDataToWrite() const {
  return write_blocked_streams_.HasWriteBlockedCryptoOrHeadersStream() ||
         write_blocked_streams_.HasWriteBlockedDataStreams() ||
         connection_->HasQueuedData();
}

void QuicSession::PostProcessAfterData() {
  STLDeleteElements(&closed_streams_);

  if (connection()->connected() &&
      locally_closed_streams_highest_offset_.size() > max_open_streams_) {
    // A buggy client may fail to send FIN/RSTs. Don't tolerate this.
    connection_->SendConnectionClose(QUIC_TOO_MANY_UNFINISHED_STREAMS);
  }
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

}  // namespace net
