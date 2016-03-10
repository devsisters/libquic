// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_spdy_session.h"

#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_headers_stream.h"

namespace net {

QuicSpdySession::QuicSpdySession(QuicConnection* connection,
                                 const QuicConfig& config)
    : QuicSession(connection, config) {}

QuicSpdySession::~QuicSpdySession() {}

void QuicSpdySession::Initialize() {
  QuicSession::Initialize();

  if (perspective() == Perspective::IS_SERVER) {
    set_largest_peer_created_stream_id(kHeadersStreamId);
  } else {
    QuicStreamId headers_stream_id = GetNextOutgoingStreamId();
    DCHECK_EQ(headers_stream_id, kHeadersStreamId);
  }

  headers_stream_.reset(new QuicHeadersStream(this));
  DCHECK_EQ(kHeadersStreamId, headers_stream_->id());
  static_streams()[kHeadersStreamId] = headers_stream_.get();
}

void QuicSpdySession::OnStreamHeaders(QuicStreamId stream_id,
                                      StringPiece headers_data) {
  QuicSpdyStream* stream = GetSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnStreamHeaders(headers_data);
}

void QuicSpdySession::OnStreamHeadersPriority(QuicStreamId stream_id,
                                              SpdyPriority priority) {
  QuicSpdyStream* stream = GetSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnStreamHeadersPriority(priority);
}

void QuicSpdySession::OnStreamHeadersComplete(QuicStreamId stream_id,
                                              bool fin,
                                              size_t frame_len) {
  QuicSpdyStream* stream = GetSpdyDataStream(stream_id);
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
    SpdyPriority priority,
    QuicAckListenerInterface* ack_notifier_delegate) {
  return headers_stream_->WriteHeaders(id, headers, fin, priority,
                                       ack_notifier_delegate);
}

void QuicSpdySession::OnHeadersHeadOfLineBlocking(QuicTime::Delta delta) {
  // Implemented in Chromium for stats tracking.
}

void QuicSpdySession::RegisterStreamPriority(QuicStreamId id,
                                             SpdyPriority priority) {
  write_blocked_streams()->RegisterStream(id, priority);
}

void QuicSpdySession::UnregisterStreamPriority(QuicStreamId id) {
  write_blocked_streams()->UnregisterStream(id);
}

void QuicSpdySession::UpdateStreamPriority(QuicStreamId id,
                                           SpdyPriority new_priority) {
  write_blocked_streams()->UpdateStreamPriority(id, new_priority);
}

QuicSpdyStream* QuicSpdySession::GetSpdyDataStream(
    const QuicStreamId stream_id) {
  return static_cast<QuicSpdyStream*>(GetOrCreateDynamicStream(stream_id));
}

void QuicSpdySession::OnPromiseHeaders(QuicStreamId stream_id,
                                       StringPiece headers_data) {
  QUIC_BUG << "OnPromiseHeaders should be overriden in client code.";
  connection()->CloseConnection(QUIC_INTERNAL_ERROR,
                                ConnectionCloseSource::FROM_SELF);
}

void QuicSpdySession::OnPromiseHeadersComplete(QuicStreamId stream_id,
                                               QuicStreamId promised_stream_id,
                                               size_t frame_len) {
  QUIC_BUG << "OnPromiseHeadersComplete shoule be overriden in client code.";
  connection()->CloseConnection(QUIC_INTERNAL_ERROR,
                                ConnectionCloseSource::FROM_SELF);
}

}  // namespace net
