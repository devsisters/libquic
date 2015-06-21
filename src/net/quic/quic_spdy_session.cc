// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_spdy_session.h"

#include "net/quic/quic_headers_stream.h"

namespace net {

QuicSpdySession::QuicSpdySession(QuicConnection* connection,
                                 const QuicConfig& config)
    : QuicSession(connection, config) {
}

QuicSpdySession::~QuicSpdySession() {
}

void QuicSpdySession::Initialize() {
  QuicSession::Initialize();

  if (perspective() == Perspective::IS_SERVER) {
    set_largest_peer_created_stream_id(kHeadersStreamId);
  } else {
    QuicStreamId headers_stream_id = GetNextStreamId();
    DCHECK_EQ(headers_stream_id, kHeadersStreamId);
  }

  headers_stream_.reset(new QuicHeadersStream(this));
  DCHECK_EQ(kHeadersStreamId, headers_stream_->id());
  static_streams()[kHeadersStreamId] = headers_stream_.get();
}

void QuicSpdySession::OnStreamHeaders(QuicStreamId stream_id,
                                      StringPiece headers_data) {
  QuicDataStream* stream = GetSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnStreamHeaders(headers_data);
}

void QuicSpdySession::OnStreamHeadersPriority(QuicStreamId stream_id,
                                              QuicPriority priority) {
  QuicDataStream* stream = GetSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnStreamHeadersPriority(priority);
}

void QuicSpdySession::OnStreamHeadersComplete(QuicStreamId stream_id,
                                              bool fin,
                                              size_t frame_len) {
  QuicDataStream* stream = GetSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnStreamHeadersComplete(fin, frame_len);
}

size_t QuicSpdySession::WriteHeaders(
    QuicStreamId id,
    const SpdyHeaderBlock& headers,
    bool fin,
    QuicPriority priority,
    QuicAckNotifier::DelegateInterface* ack_notifier_delegate) {
  return headers_stream_->WriteHeaders(id, headers, fin, priority,
                                       ack_notifier_delegate);
}

QuicDataStream* QuicSpdySession::GetSpdyDataStream(
    const QuicStreamId stream_id) {
  return static_cast<QuicDataStream*>(GetDynamicStream(stream_id));
}

}  // namespace net
