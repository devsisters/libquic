// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_spdy_stream.h"

#include "base/logging.h"
#include "net/quic/quic_spdy_session.h"
#include "net/quic/quic_utils.h"
#include "net/quic/quic_write_blocked_list.h"

using base::StringPiece;
using std::min;

namespace net {

#define ENDPOINT                                                               \
  (session()->perspective() == Perspective::IS_SERVER ? "Server: " : "Client:" \
                                                                     " ")

namespace {

// This is somewhat arbitrary.  It's possible, but unlikely, we will either fail
// to set a priority client-side, or cancel a stream before stripping the
// priority from the wire server-side.  In either case, start out with a
// priority in the middle.
QuicPriority kDefaultPriority = 3;

}  // namespace

QuicSpdyStream::QuicSpdyStream(QuicStreamId id, QuicSpdySession* spdy_session)
    : ReliableQuicStream(id, spdy_session),
      spdy_session_(spdy_session),
      visitor_(nullptr),
      headers_decompressed_(false),
      priority_(kDefaultPriority) {
  DCHECK_NE(kCryptoStreamId, id);
  // Don't receive any callbacks from the sequencer until headers
  // are complete.
  sequencer()->SetBlockedUntilFlush();
}

QuicSpdyStream::~QuicSpdyStream() {}

void QuicSpdyStream::CloseWriteSide() {
  if (version() > QUIC_VERSION_28 && !fin_received() && !rst_received() &&
      sequencer()->ignore_read_data() && !rst_sent()) {
    DCHECK(fin_sent());
    // Tell the peer to stop sending further data.
    DVLOG(1) << ENDPOINT << "Send QUIC_STREAM_NO_ERROR on stream " << id();
    Reset(QUIC_STREAM_NO_ERROR);
  }

  ReliableQuicStream::CloseWriteSide();
}

void QuicSpdyStream::StopReading() {
  if (version() > QUIC_VERSION_28 && !fin_received() && !rst_received() &&
      write_side_closed() && !rst_sent()) {
    DCHECK(fin_sent());
    // Tell the peer to stop sending further data.
    DVLOG(1) << ENDPOINT << "Send QUIC_STREAM_NO_ERROR on stream " << id();
    Reset(QUIC_STREAM_NO_ERROR);
  }
  ReliableQuicStream::StopReading();
}

size_t QuicSpdyStream::WriteHeaders(
    const SpdyHeaderBlock& header_block,
    bool fin,
    QuicAckListenerInterface* ack_notifier_delegate) {
  size_t bytes_written = spdy_session_->WriteHeaders(
      id(), header_block, fin, priority_, ack_notifier_delegate);
  if (fin) {
    // TODO(rch): Add test to ensure fin_sent_ is set whenever a fin is sent.
    set_fin_sent(true);
    CloseWriteSide();
  }
  return bytes_written;
}

size_t QuicSpdyStream::Readv(const struct iovec* iov, size_t iov_len) {
  DCHECK(FinishedReadingHeaders());
  return sequencer()->Readv(iov, iov_len);
}

int QuicSpdyStream::GetReadableRegions(iovec* iov, size_t iov_len) const {
  DCHECK(FinishedReadingHeaders());
  return sequencer()->GetReadableRegions(iov, iov_len);
}

void QuicSpdyStream::MarkConsumed(size_t num_bytes) {
  DCHECK(FinishedReadingHeaders());
  return sequencer()->MarkConsumed(num_bytes);
}

bool QuicSpdyStream::IsDoneReading() const {
  if (!headers_decompressed_ || !decompressed_headers_.empty()) {
    return false;
  }
  return sequencer()->IsClosed();
}

bool QuicSpdyStream::HasBytesToRead() const {
  return !decompressed_headers_.empty() || sequencer()->HasBytesToRead();
}

void QuicSpdyStream::MarkHeadersConsumed(size_t bytes_consumed) {
  decompressed_headers_.erase(0, bytes_consumed);
  if (FinishedReadingHeaders()) {
    sequencer()->SetUnblocked();
  }
}

void QuicSpdyStream::set_priority(QuicPriority priority) {
  DCHECK_EQ(0u, stream_bytes_written());
  priority_ = priority;
}

QuicPriority QuicSpdyStream::EffectivePriority() const {
  return priority();
}

void QuicSpdyStream::OnStreamHeaders(StringPiece headers_data) {
  headers_data.AppendToString(&decompressed_headers_);
}

void QuicSpdyStream::OnStreamHeadersPriority(QuicPriority priority) {
  DCHECK_EQ(Perspective::IS_SERVER, session()->connection()->perspective());
  set_priority(priority);
}

void QuicSpdyStream::OnStreamHeadersComplete(bool fin, size_t frame_len) {
  headers_decompressed_ = true;
  if (fin) {
    OnStreamFrame(QuicStreamFrame(id(), fin, 0, StringPiece()));
  }
  if (FinishedReadingHeaders()) {
    sequencer()->SetUnblocked();
  }
}

void QuicSpdyStream::OnStreamReset(const QuicRstStreamFrame& frame) {
  if (frame.error_code != QUIC_STREAM_NO_ERROR ||
      version() <= QUIC_VERSION_28) {
    ReliableQuicStream::OnStreamReset(frame);
    return;
  }
  DVLOG(1) << "Received QUIC_STREAM_NO_ERROR, not discarding response";
  set_rst_received(true);
  MaybeIncreaseHighestReceivedOffset(frame.byte_offset);
  set_stream_error(frame.error_code);
  CloseWriteSide();
}

void QuicSpdyStream::OnClose() {
  ReliableQuicStream::OnClose();

  if (visitor_) {
    Visitor* visitor = visitor_;
    // Calling Visitor::OnClose() may result the destruction of the visitor,
    // so we need to ensure we don't call it again.
    visitor_ = nullptr;
    visitor->OnClose(this);
  }
}

bool QuicSpdyStream::FinishedReadingHeaders() const {
  return headers_decompressed_ && decompressed_headers_.empty();
}

}  // namespace net
