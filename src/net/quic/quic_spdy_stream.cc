// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_spdy_stream.h"

#include <utility>

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_spdy_session.h"
#include "net/quic/quic_utils.h"
#include "net/quic/quic_write_blocked_list.h"
#include "net/quic/spdy_utils.h"

using base::IntToString;
using base::StringPiece;
using std::min;
using std::string;

namespace net {

#define ENDPOINT                                                               \
  (session()->perspective() == Perspective::IS_SERVER ? "Server: " : "Client:" \
                                                                     " ")

QuicSpdyStream::QuicSpdyStream(QuicStreamId id, QuicSpdySession* spdy_session)
    : ReliableQuicStream(id, spdy_session),
      spdy_session_(spdy_session),
      visitor_(nullptr),
      headers_decompressed_(false),
      priority_(kDefaultPriority),
      trailers_decompressed_(false),
      trailers_delivered_(false) {
  DCHECK_NE(kCryptoStreamId, id);
  // Don't receive any callbacks from the sequencer until headers
  // are complete.
  sequencer()->SetBlockedUntilFlush();
  spdy_session_->RegisterStreamPriority(id, priority_);
}

QuicSpdyStream::~QuicSpdyStream() {
  if (spdy_session_ != nullptr) {
    spdy_session_->UnregisterStreamPriority(id());
  }
}

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
    SpdyHeaderBlock header_block,
    bool fin,
    QuicAckListenerInterface* ack_notifier_delegate) {
  size_t bytes_written = spdy_session_->WriteHeaders(
      id(), std::move(header_block), fin, priority_, ack_notifier_delegate);
  if (fin) {
    // TODO(rch): Add test to ensure fin_sent_ is set whenever a fin is sent.
    set_fin_sent(true);
    CloseWriteSide();
  }
  return bytes_written;
}

void QuicSpdyStream::WriteOrBufferBody(
    const string& data,
    bool fin,
    QuicAckListenerInterface* ack_notifier_delegate) {
  WriteOrBufferData(data, fin, ack_notifier_delegate);
}

size_t QuicSpdyStream::WriteTrailers(
    SpdyHeaderBlock trailer_block,
    QuicAckListenerInterface* ack_notifier_delegate) {
  if (fin_sent()) {
    QUIC_BUG << "Trailers cannot be sent after a FIN.";
    return 0;
  }

  // The header block must contain the final offset for this stream, as the
  // trailers may be processed out of order at the peer.
  DVLOG(1) << "Inserting trailer: (" << kFinalOffsetHeaderKey << ", "
           << stream_bytes_written() + queued_data_bytes() << ")";
  trailer_block.insert(std::make_pair(
      kFinalOffsetHeaderKey,
      IntToString(stream_bytes_written() + queued_data_bytes())));

  // Write the trailing headers with a FIN, and close stream for writing:
  // trailers are the last thing to be sent on a stream.
  const bool kFin = true;
  size_t bytes_written = spdy_session_->WriteHeaders(
      id(), std::move(trailer_block), kFin, priority_, ack_notifier_delegate);
  set_fin_sent(kFin);

  // Trailers are the last thing to be sent on a stream, but if there is still
  // queued data then CloseWriteSide() will cause it never to be sent.
  if (queued_data_bytes() == 0) {
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
  bool done_reading_headers = FinishedReadingHeaders();
  bool done_reading_body = sequencer()->IsClosed();
  bool done_reading_trailers = FinishedReadingTrailers();
  return done_reading_headers && done_reading_body && done_reading_trailers;
}

bool QuicSpdyStream::HasBytesToRead() const {
  bool headers_to_read = !decompressed_headers_.empty();
  bool body_to_read = sequencer()->HasBytesToRead();
  bool trailers_to_read = !decompressed_trailers_.empty();
  return headers_to_read || body_to_read || trailers_to_read;
}

void QuicSpdyStream::MarkHeadersConsumed(size_t bytes_consumed) {
  decompressed_headers_.erase(0, bytes_consumed);
  if (FinishedReadingHeaders()) {
    sequencer()->SetUnblocked();
  }
}

void QuicSpdyStream::MarkTrailersConsumed(size_t bytes_consumed) {
  decompressed_trailers_.erase(0, bytes_consumed);
}

void QuicSpdyStream::MarkTrailersDelivered() {
  trailers_delivered_ = true;
}

void QuicSpdyStream::ConsumeHeaderList() {
  header_list_.Clear();
  if (FinishedReadingHeaders()) {
    sequencer()->SetUnblocked();
  }
}

void QuicSpdyStream::SetPriority(SpdyPriority priority) {
  DCHECK_EQ(0u, stream_bytes_written());
  spdy_session_->UpdateStreamPriority(id(), priority);
  priority_ = priority;
}

void QuicSpdyStream::OnStreamHeaders(StringPiece headers_data) {
  if (!headers_decompressed_) {
    headers_data.AppendToString(&decompressed_headers_);
  } else {
    DCHECK(!trailers_decompressed_);
    headers_data.AppendToString(&decompressed_trailers_);
  }
}

void QuicSpdyStream::OnStreamHeadersPriority(SpdyPriority priority) {
  DCHECK_EQ(Perspective::IS_SERVER, session()->connection()->perspective());
  SetPriority(priority);
}

void QuicSpdyStream::OnStreamHeadersComplete(bool fin, size_t frame_len) {
  if (!headers_decompressed_) {
    OnInitialHeadersComplete(fin, frame_len);
  } else {
    OnTrailingHeadersComplete(fin, frame_len);
  }
}

void QuicSpdyStream::OnStreamHeaderList(bool fin,
                                        size_t frame_len,
                                        const QuicHeaderList& header_list) {
  if (!headers_decompressed_) {
    OnInitialHeadersComplete(fin, frame_len, header_list);
  } else {
    OnTrailingHeadersComplete(fin, frame_len, header_list);
  }
}

void QuicSpdyStream::OnInitialHeadersComplete(bool fin, size_t /*frame_len*/) {
  headers_decompressed_ = true;
  if (fin) {
    OnStreamFrame(QuicStreamFrame(id(), fin, 0, StringPiece()));
  }
  if (FinishedReadingHeaders()) {
    sequencer()->SetUnblocked();
  }
}

void QuicSpdyStream::OnInitialHeadersComplete(
    bool fin,
    size_t /*frame_len*/,
    const QuicHeaderList& header_list) {
  headers_decompressed_ = true;
  header_list_ = header_list;
  if (fin) {
    OnStreamFrame(QuicStreamFrame(id(), fin, 0, StringPiece()));
  }
  if (FinishedReadingHeaders()) {
    sequencer()->SetUnblocked();
  }
}

void QuicSpdyStream::OnPromiseHeaders(StringPiece headers_data) {
  headers_data.AppendToString(&decompressed_headers_);
}

void QuicSpdyStream::OnPromiseHeadersComplete(
    QuicStreamId /* promised_stream_id */,
    size_t /* frame_len */) {
  // To be overridden in QuicSpdyClientStream.  Not supported on
  // server side.
  session()->connection()->CloseConnection(
      QUIC_INVALID_HEADERS_STREAM_DATA, "Promise headers received by server",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  return;
}

void QuicSpdyStream::OnPromiseHeaderList(
    QuicStreamId /* promised_id */,
    size_t /* frame_len */,
    const QuicHeaderList& /*header_list */) {
  // To be overridden in QuicSpdyClientStream.  Not supported on
  // server side.
  session()->connection()->CloseConnection(
      QUIC_INVALID_HEADERS_STREAM_DATA, "Promise headers received by server",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  return;
}

void QuicSpdyStream::OnTrailingHeadersComplete(bool fin, size_t /*frame_len*/) {
  DCHECK(!trailers_decompressed_);
  if (fin_received()) {
    DLOG(ERROR) << "Received Trailers after FIN, on stream: " << id();
    session()->connection()->CloseConnection(
        QUIC_INVALID_HEADERS_STREAM_DATA, "Trailers after fin",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  if (!fin) {
    DLOG(ERROR) << "Trailers must have FIN set, on stream: " << id();
    session()->connection()->CloseConnection(
        QUIC_INVALID_HEADERS_STREAM_DATA, "Fin missing from trailers",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  size_t final_byte_offset = 0;
  if (!SpdyUtils::ParseTrailers(decompressed_trailers().data(),
                                decompressed_trailers().length(),
                                &final_byte_offset, &received_trailers_)) {
    DLOG(ERROR) << "Trailers are malformed: " << id();
    session()->connection()->CloseConnection(
        QUIC_INVALID_HEADERS_STREAM_DATA, "Trailers are malformed",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  // The data on this stream ends at |final_byte_offset|.
  DVLOG(1) << "Stream ends at byte offset: " << final_byte_offset
           << "  currently read: " << stream_bytes_read();

  OnStreamFrame(QuicStreamFrame(id(), fin, final_byte_offset, StringPiece()));
  trailers_decompressed_ = true;
}

void QuicSpdyStream::OnTrailingHeadersComplete(
    bool fin,
    size_t /*frame_len*/,
    const QuicHeaderList& header_list) {
  DCHECK(!trailers_decompressed_);
  if (fin_received()) {
    DLOG(ERROR) << "Received Trailers after FIN, on stream: " << id();
    session()->connection()->CloseConnection(
        QUIC_INVALID_HEADERS_STREAM_DATA, "Trailers after fin",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  if (!fin) {
    DLOG(ERROR) << "Trailers must have FIN set, on stream: " << id();
    session()->connection()->CloseConnection(
        QUIC_INVALID_HEADERS_STREAM_DATA, "Fin missing from trailers",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  size_t final_byte_offset = 0;
  if (!SpdyUtils::CopyAndValidateTrailers(header_list, &final_byte_offset,
                                          &received_trailers_)) {
    DLOG(ERROR) << "Trailers are malformed: " << id();
    session()->connection()->CloseConnection(
        QUIC_INVALID_HEADERS_STREAM_DATA, "Trailers are malformed",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  OnStreamFrame(QuicStreamFrame(id(), fin, final_byte_offset, StringPiece()));
  trailers_decompressed_ = true;
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
  return headers_decompressed_ && decompressed_headers_.empty() &&
         header_list_.empty();
}

bool QuicSpdyStream::ParseHeaderStatusCode(const SpdyHeaderBlock& header,
                                           int* status_code) const {
  SpdyHeaderBlock::const_iterator it = header.find(":status");
  if (it == header.end()) {
    return false;
  }
  const StringPiece status(it->second);
  if (status.size() != 3) {
    return false;
  }
  // First character must be an integer in range [1,5].
  if (status[0] < '1' || status[0] > '5') {
    return false;
  }
  // The remaining two characters must be integers.
  if (!isdigit(status[1]) || !isdigit(status[2])) {
    return false;
  }
  return StringToInt(status, status_code);
}

bool QuicSpdyStream::FinishedReadingTrailers() const {
  // If no further trailing headers are expected, and the decompressed trailers
  // (if any) have been consumed, then reading of trailers is finished.
  if (!fin_received()) {
    return false;
  } else if (!trailers_decompressed_) {
    return true;
  } else {
    return trailers_delivered_ && decompressed_trailers_.empty();
  }
}

SpdyPriority QuicSpdyStream::priority() const {
  return priority_;
}

void QuicSpdyStream::ClearSession() {
  spdy_session_ = nullptr;
}

}  // namespace net
