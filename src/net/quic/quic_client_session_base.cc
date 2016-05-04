// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_client_session_base.h"

#include "net/quic/quic_client_promised_info.h"
#include "net/quic/quic_flags.h"
#include "net/quic/spdy_utils.h"

using base::StringPiece;
using std::string;

namespace net {

QuicClientSessionBase::QuicClientSessionBase(
    QuicConnection* connection,
    QuicClientPushPromiseIndex* push_promise_index,
    const QuicConfig& config)
    : QuicSpdySession(connection, config),
      push_promise_index_(push_promise_index),
      largest_promised_stream_id_(kInvalidStreamId) {}

QuicClientSessionBase::~QuicClientSessionBase() {
  //  all promised streams for this session
  for (auto& it : promised_by_id_) {
    DVLOG(1) << "erase stream " << it.first << " url " << it.second->url();
    push_promise_index_->promised_by_url()->erase(it.second->url());
  }
}

void QuicClientSessionBase::OnCryptoHandshakeEvent(CryptoHandshakeEvent event) {
  QuicSession::OnCryptoHandshakeEvent(event);
}

void QuicClientSessionBase::OnPromiseHeaders(QuicStreamId stream_id,
                                             StringPiece headers_data) {
  QuicSpdyStream* stream = GetSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnPromiseHeaders(headers_data);
}

void QuicClientSessionBase::OnInitialHeadersComplete(
    QuicStreamId stream_id,
    const SpdyHeaderBlock& response_headers) {
  // Note that the strong ordering of the headers stream means that
  // QuicSpdyClientStream::OnPromiseHeadersComplete must have already
  // been called (on the associated stream) if this is a promised
  // stream. However, this stream may not have existed at this time,
  // hence the need to query the session.
  QuicClientPromisedInfo* promised = GetPromisedById(stream_id);
  if (!promised)
    return;

  promised->OnResponseHeaders(response_headers);
}

void QuicClientSessionBase::OnPromiseHeadersComplete(
    QuicStreamId stream_id,
    QuicStreamId promised_stream_id,
    size_t frame_len) {
  if (promised_stream_id != kInvalidStreamId &&
      promised_stream_id <= largest_promised_stream_id_) {
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID,
        "Received push stream id lesser or equal to the"
        " last accepted before",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  largest_promised_stream_id_ = promised_stream_id;

  QuicSpdyStream* stream = GetSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnPromiseHeadersComplete(promised_stream_id, frame_len);
}

void QuicClientSessionBase::OnPromiseHeaderList(
    QuicStreamId stream_id,
    QuicStreamId promised_stream_id,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  if (promised_stream_id != kInvalidStreamId &&
      promised_stream_id <= largest_promised_stream_id_) {
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID,
        "Received push stream id lesser or equal to the"
        " last accepted before",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  largest_promised_stream_id_ = promised_stream_id;

  QuicSpdyStream* stream = GetSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnPromiseHeaderList(promised_stream_id, frame_len, header_list);
}

void QuicClientSessionBase::HandlePromised(QuicStreamId /* associated_id */,
                                           QuicStreamId id,
                                           const SpdyHeaderBlock& headers) {
  // Due to pathalogical packet re-ordering, it is possible that
  // frames for the promised stream have already arrived, and the
  // promised stream could be active or closed.
  if (IsClosedStream(id)) {
    // There was a RST on the data stream already, perhaps
    // QUIC_REFUSED_STREAM?
    DVLOG(1) << "Promise ignored for stream " << id
             << " that is already closed";
    return;
  }

  if (push_promise_index_->promised_by_url()->size() >= get_max_promises()) {
    DVLOG(1) << "Too many promises, rejecting promise for stream " << id;
    ResetPromised(id, QUIC_REFUSED_STREAM);
    return;
  }

  const string url = SpdyUtils::GetUrlFromHeaderBlock(headers);
  QuicClientPromisedInfo* old_promised = GetPromisedByUrl(url);
  if (old_promised) {
    DVLOG(1) << "Promise for stream " << id << " is duplicate URL " << url
             << " of previous promise for stream " << old_promised->id();
    ResetPromised(id, QUIC_DUPLICATE_PROMISE_URL);
    return;
  }

  if (GetPromisedById(id)) {
    // OnPromiseHeadersComplete() would have closed the connection if
    // promised id is a duplicate.
    QUIC_BUG << "Duplicate promise for id " << id;
    return;
  }

  QuicClientPromisedInfo* promised = new QuicClientPromisedInfo(this, id, url);
  std::unique_ptr<QuicClientPromisedInfo> promised_owner(promised);
  promised->Init();
  DVLOG(1) << "stream " << id << " emplace url " << url;
  (*push_promise_index_->promised_by_url())[url] = promised;
  promised_by_id_[id] = std::move(promised_owner);
  promised->OnPromiseHeaders(headers);
}

QuicClientPromisedInfo* QuicClientSessionBase::GetPromisedByUrl(
    const string& url) {
  QuicPromisedByUrlMap::iterator it =
      push_promise_index_->promised_by_url()->find(url);
  if (it != push_promise_index_->promised_by_url()->end()) {
    return it->second;
  }
  return nullptr;
}

QuicClientPromisedInfo* QuicClientSessionBase::GetPromisedById(
    const QuicStreamId id) {
  QuicPromisedByIdMap::iterator it = promised_by_id_.find(id);
  if (it != promised_by_id_.end()) {
    return it->second.get();
  }
  return nullptr;
}

QuicSpdyStream* QuicClientSessionBase::GetPromisedStream(
    const QuicStreamId id) {
  if (IsClosedStream(id)) {
    return nullptr;
  }
  StreamMap::iterator it = dynamic_streams().find(id);
  if (it != dynamic_streams().end()) {
    return static_cast<QuicSpdyStream*>(it->second);
  }
  QUIC_BUG << "Open promised stream " << id << " is missing!";
  return nullptr;
}

void QuicClientSessionBase::DeletePromised(QuicClientPromisedInfo* promised) {
  push_promise_index_->promised_by_url()->erase(promised->url());
  // Since promised_by_id_ contains the unique_ptr, this will destroy
  // promised.
  promised_by_id_.erase(promised->id());
}

void QuicClientSessionBase::ResetPromised(QuicStreamId id,
                                          QuicRstStreamErrorCode error_code) {
  SendRstStream(id, error_code, 0);
  if (!IsOpenStream(id)) {
    MaybeIncreaseLargestPeerStreamId(id);
    InsertLocallyClosedStreamsHighestOffset(id, 0);
  }
}

}  // namespace net
