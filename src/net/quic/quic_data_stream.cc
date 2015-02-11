// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_data_stream.h"

#include "base/logging.h"
#include "net/quic/quic_session.h"
#include "net/quic/quic_utils.h"
#include "net/quic/quic_write_blocked_list.h"

using base::StringPiece;
using std::min;

namespace net {

#define ENDPOINT (session()->is_server() ? "Server: " : " Client: ")

namespace {

// This is somewhat arbitrary.  It's possible, but unlikely, we will either fail
// to set a priority client-side, or cancel a stream before stripping the
// priority from the wire server-side.  In either case, start out with a
// priority in the middle.
QuicPriority kDefaultPriority = 3;

}  // namespace

QuicDataStream::QuicDataStream(QuicStreamId id,
                               QuicSession* session)
    : ReliableQuicStream(id, session),
      visitor_(nullptr),
      headers_decompressed_(false),
      priority_(kDefaultPriority),
      decompression_failed_(false),
      priority_parsed_(false) {
  DCHECK_NE(kCryptoStreamId, id);
  // Don't receive any callbacks from the sequencer until headers
  // are complete.
  sequencer()->SetBlockedUntilFlush();
}

QuicDataStream::~QuicDataStream() {
}

size_t QuicDataStream::WriteHeaders(
    const SpdyHeaderBlock& header_block,
    bool fin,
    QuicAckNotifier::DelegateInterface* ack_notifier_delegate) {
  size_t bytes_written = session()->WriteHeaders(
      id(), header_block, fin, priority_, ack_notifier_delegate);
  if (fin) {
    // TODO(rch): Add test to ensure fin_sent_ is set whenever a fin is sent.
    set_fin_sent(true);
    CloseWriteSide();
  }
  return bytes_written;
}

size_t QuicDataStream::Readv(const struct iovec* iov, size_t iov_len) {
  if (FinishedReadingHeaders()) {
    // If the headers have been read, simply delegate to the sequencer's
    // Readv method.
    return sequencer()->Readv(iov, iov_len);
  }
  // Otherwise, copy decompressed header data into |iov|.
  size_t bytes_consumed = 0;
  size_t iov_index = 0;
  while (iov_index < iov_len &&
         decompressed_headers_.length() > bytes_consumed) {
    size_t bytes_to_read = min(iov[iov_index].iov_len,
                               decompressed_headers_.length() - bytes_consumed);
    char* iov_ptr = static_cast<char*>(iov[iov_index].iov_base);
    memcpy(iov_ptr,
           decompressed_headers_.data() + bytes_consumed, bytes_to_read);
    bytes_consumed += bytes_to_read;
    ++iov_index;
  }
  decompressed_headers_.erase(0, bytes_consumed);
  if (FinishedReadingHeaders()) {
    sequencer()->FlushBufferedFrames();
  }
  return bytes_consumed;
}

int QuicDataStream::GetReadableRegions(iovec* iov, size_t iov_len) {
  if (FinishedReadingHeaders()) {
    return sequencer()->GetReadableRegions(iov, iov_len);
  }
  if (iov_len == 0) {
    return 0;
  }
  iov[0].iov_base = static_cast<void*>(
      const_cast<char*>(decompressed_headers_.data()));
  iov[0].iov_len = decompressed_headers_.length();
  return 1;
}

bool QuicDataStream::IsDoneReading() const {
  if (!headers_decompressed_ || !decompressed_headers_.empty()) {
    return false;
  }
  return sequencer()->IsClosed();
}

bool QuicDataStream::HasBytesToRead() const {
  return !decompressed_headers_.empty() || sequencer()->HasBytesToRead();
}

void QuicDataStream::set_priority(QuicPriority priority) {
  DCHECK_EQ(0u, stream_bytes_written());
  priority_ = priority;
}

QuicPriority QuicDataStream::EffectivePriority() const {
  return priority();
}

uint32 QuicDataStream::ProcessRawData(const char* data, uint32 data_len) {
  if (!FinishedReadingHeaders()) {
    LOG(DFATAL) << "ProcessRawData called before headers have been finished";
    return 0;
  }
  return ProcessData(data, data_len);
}

const IPEndPoint& QuicDataStream::GetPeerAddress() {
  return session()->peer_address();
}

#if 0
bool QuicDataStream::GetSSLInfo(SSLInfo* ssl_info) {
  return session()->GetSSLInfo(ssl_info);
}
#endif

uint32 QuicDataStream::ProcessHeaderData() {
  if (decompressed_headers_.empty()) {
    return 0;
  }

  size_t bytes_processed = ProcessData(decompressed_headers_.data(),
                                       decompressed_headers_.length());
  if (bytes_processed == decompressed_headers_.length()) {
    decompressed_headers_.clear();
  } else {
    decompressed_headers_ = decompressed_headers_.erase(0, bytes_processed);
  }
  return bytes_processed;
}

void QuicDataStream::OnStreamHeaders(StringPiece headers_data) {
  headers_data.AppendToString(&decompressed_headers_);
  ProcessHeaderData();
}

void QuicDataStream::OnStreamHeadersPriority(QuicPriority priority) {
  DCHECK(session()->connection()->is_server());
  set_priority(priority);
}

void QuicDataStream::OnStreamHeadersComplete(bool fin, size_t frame_len) {
  headers_decompressed_ = true;
  if (fin) {
    sequencer()->OnStreamFrame(QuicStreamFrame(id(), fin, 0, IOVector()));
  }
  ProcessHeaderData();
  if (FinishedReadingHeaders()) {
    sequencer()->FlushBufferedFrames();
  }
}

void QuicDataStream::OnClose() {
  ReliableQuicStream::OnClose();

  if (visitor_) {
    Visitor* visitor = visitor_;
    // Calling Visitor::OnClose() may result the destruction of the visitor,
    // so we need to ensure we don't call it again.
    visitor_ = nullptr;
    visitor->OnClose(this);
  }
}

bool QuicDataStream::FinishedReadingHeaders() {
  return headers_decompressed_ && decompressed_headers_.empty();
}

}  // namespace net
