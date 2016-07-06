// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_headers_stream.h"

#include <utility>

#include "base/macros.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_header_list.h"
#include "net/quic/quic_spdy_session.h"
#include "net/quic/quic_time.h"
#include "net/spdy/spdy_protocol.h"

using base::StringPiece;
using net::HTTP2;
using net::SpdyFrameType;
using std::string;

namespace net {

namespace {

class HeaderTableDebugVisitor : public HpackHeaderTable::DebugVisitorInterface {
 public:
  HeaderTableDebugVisitor(
      const QuicClock* clock,
      std::unique_ptr<QuicHeadersStream::HpackDebugVisitor> visitor)
      : clock_(clock), headers_stream_hpack_visitor_(std::move(visitor)) {}

  int64_t OnNewEntry(const HpackEntry& entry) override {
    DVLOG(1) << entry.GetDebugString();
    return clock_->ApproximateNow().Subtract(QuicTime::Zero()).ToMicroseconds();
  }

  void OnUseEntry(const HpackEntry& entry) override {
    const QuicTime::Delta elapsed(
        clock_->ApproximateNow()
            .Subtract(QuicTime::Delta::FromMicroseconds(entry.time_added()))
            .Subtract(QuicTime::Zero()));
    DVLOG(1) << entry.GetDebugString() << " " << elapsed.ToMilliseconds()
             << " ms";
    headers_stream_hpack_visitor_->OnUseEntry(elapsed);
  }

 private:
  const QuicClock* clock_;
  std::unique_ptr<QuicHeadersStream::HpackDebugVisitor>
      headers_stream_hpack_visitor_;

  DISALLOW_COPY_AND_ASSIGN(HeaderTableDebugVisitor);
};

}  // namespace

QuicHeadersStream::HpackDebugVisitor::HpackDebugVisitor() {}

QuicHeadersStream::HpackDebugVisitor::~HpackDebugVisitor() {}

// A SpdyFramer visitor which passed SYN_STREAM and SYN_REPLY frames to
// the QuicSpdyStream, and closes the connection if any unexpected frames
// are received.
class QuicHeadersStream::SpdyFramerVisitor
    : public SpdyFramerVisitorInterface,
      public SpdyFramerDebugVisitorInterface {
 public:
  explicit SpdyFramerVisitor(QuicHeadersStream* stream) : stream_(stream) {}

  // SpdyFramerVisitorInterface implementation
  void OnSynStream(SpdyStreamId stream_id,
                   SpdyStreamId associated_stream_id,
                   SpdyPriority priority,
                   bool fin,
                   bool unidirectional) override {
    CloseConnection("SPDY SYN_STREAM frame received.");
  }

  void OnSynReply(SpdyStreamId stream_id, bool fin) override {
    CloseConnection("SPDY SYN_REPLY frame received.");
  }

  bool OnControlFrameHeaderData(SpdyStreamId stream_id,
                                const char* header_data,
                                size_t len) override {
    if (!stream_->IsConnected()) {
      return false;
    }
    stream_->OnControlFrameHeaderData(stream_id, header_data, len);
    return true;
  }

  void OnStreamFrameData(SpdyStreamId stream_id,
                         const char* data,
                         size_t len) override {
    CloseConnection("SPDY DATA frame received.");
  }

  void OnStreamEnd(SpdyStreamId stream_id) override {
    // The framer invokes OnStreamEnd after processing a SYN_STREAM
    // or SYN_REPLY frame that had the fin bit set.
  }

  void OnStreamPadding(SpdyStreamId stream_id, size_t len) override {
    CloseConnection("SPDY frame padding received.");
  }

  SpdyHeadersHandlerInterface* OnHeaderFrameStart(
      SpdyStreamId /* stream_id */) override {
    return &header_list_;
  }

  void OnHeaderFrameEnd(SpdyStreamId /* stream_id */,
                        bool end_headers) override {
    if (end_headers) {
      if (stream_->IsConnected()) {
        stream_->OnHeaderList(header_list_);
      }
      header_list_.Clear();
    }
  }

  void OnError(SpdyFramer* framer) override {
    CloseConnection(base::StringPrintf(
        "SPDY framing error: %s",
        SpdyFramer::ErrorCodeToString(framer->error_code())));
  }

  void OnDataFrameHeader(SpdyStreamId stream_id,
                         size_t length,
                         bool fin) override {
    CloseConnection("SPDY DATA frame received.");
  }

  void OnRstStream(SpdyStreamId stream_id,
                   SpdyRstStreamStatus status) override {
    CloseConnection("SPDY RST_STREAM frame received.");
  }

  void OnSetting(SpdySettingsIds id, uint8_t flags, uint32_t value) override {
    if (!FLAGS_quic_respect_http2_settings_frame) {
      CloseConnection("SPDY SETTINGS frame received.");
      return;
    }
    switch (id) {
      case SETTINGS_HEADER_TABLE_SIZE:
        stream_->UpdateHeaderEncoderTableSize(value);
        break;
      // TODO(fayang): Need to support SETTINGS_MAX_HEADER_LIST_SIZE when
      // clients are actually sending it.
      default:
        CloseConnection("Unsupported field of HTTP/2 SETTINGS frame: " +
                        base::IntToString(id));
    }
  }

  void OnSettingsAck() override {
    if (!FLAGS_quic_respect_http2_settings_frame) {
      CloseConnection("SPDY SETTINGS frame received.");
    }
  }

  void OnSettingsEnd() override {
    if (!FLAGS_quic_respect_http2_settings_frame) {
      CloseConnection("SPDY SETTINGS frame received.");
    }
  }

  void OnPing(SpdyPingId unique_id, bool is_ack) override {
    CloseConnection("SPDY PING frame received.");
  }

  void OnGoAway(SpdyStreamId last_accepted_stream_id,
                SpdyGoAwayStatus status) override {
    CloseConnection("SPDY GOAWAY frame received.");
  }

  void OnHeaders(SpdyStreamId stream_id,
                 bool has_priority,
                 int weight,
                 SpdyStreamId parent_stream_id,
                 bool exclusive,
                 bool fin,
                 bool end) override {
    if (!stream_->IsConnected()) {
      return;
    }

    // TODO(mpw): avoid down-conversion and plumb SpdyStreamPrecedence through
    // QuicHeadersStream.
    SpdyPriority priority =
        has_priority ? Http2WeightToSpdy3Priority(weight) : 0;
    stream_->OnHeaders(stream_id, has_priority, priority, fin);
  }

  void OnWindowUpdate(SpdyStreamId stream_id, int delta_window_size) override {
    CloseConnection("SPDY WINDOW_UPDATE frame received.");
  }

  void OnPushPromise(SpdyStreamId stream_id,
                     SpdyStreamId promised_stream_id,
                     bool end) override {
    if (!stream_->supports_push_promise()) {
      CloseConnection("PUSH_PROMISE not supported.");
      return;
    }
    if (!stream_->IsConnected()) {
      return;
    }
    stream_->OnPushPromise(stream_id, promised_stream_id, end);
  }

  void OnContinuation(SpdyStreamId stream_id, bool end) override {}

  void OnPriority(SpdyStreamId stream_id,
                  SpdyStreamId parent_id,
                  int weight,
                  bool exclusive) override {
    CloseConnection("SPDY PRIORITY frame received.");
  }

  bool OnUnknownFrame(SpdyStreamId stream_id, int frame_type) override {
    CloseConnection("Unknown frame type received.");
    return false;
  }

  // SpdyFramerDebugVisitorInterface implementation
  void OnSendCompressedFrame(SpdyStreamId stream_id,
                             SpdyFrameType type,
                             size_t payload_len,
                             size_t frame_len) override {
    if (payload_len == 0) {
      QUIC_BUG << "Zero payload length.";
      return;
    }
    int compression_pct = 100 - (100 * frame_len) / payload_len;
    DVLOG(1) << "Net.QuicHpackCompressionPercentage: " << compression_pct;
    UMA_HISTOGRAM_PERCENTAGE("Net.QuicHpackCompressionPercentage",
                             compression_pct);
  }

  void OnReceiveCompressedFrame(SpdyStreamId stream_id,
                                SpdyFrameType type,
                                size_t frame_len) override {
    if (stream_->IsConnected()) {
      stream_->OnCompressedFrameSize(frame_len);
    }
  }

 private:
  void CloseConnection(const string& details) {
    if (stream_->IsConnected()) {
      stream_->CloseConnectionWithDetails(QUIC_INVALID_HEADERS_STREAM_DATA,
                                          details);
    }
  }

 private:
  QuicHeadersStream* stream_;
  QuicHeaderList header_list_;

  DISALLOW_COPY_AND_ASSIGN(SpdyFramerVisitor);
};

QuicHeadersStream::QuicHeadersStream(QuicSpdySession* session)
    : ReliableQuicStream(kHeadersStreamId, session),
      spdy_session_(session),
      stream_id_(kInvalidStreamId),
      promised_stream_id_(kInvalidStreamId),
      fin_(false),
      frame_len_(0),
      uncompressed_frame_len_(0),
      measure_headers_hol_blocking_time_(
          FLAGS_quic_measure_headers_hol_blocking_time),
      supports_push_promise_(session->perspective() == Perspective::IS_CLIENT &&
                             FLAGS_quic_supports_push_promise),
      cur_max_timestamp_(QuicTime::Zero()),
      prev_max_timestamp_(QuicTime::Zero()),
      spdy_framer_(HTTP2),
      spdy_framer_visitor_(new SpdyFramerVisitor(this)) {
  spdy_framer_.set_visitor(spdy_framer_visitor_.get());
  spdy_framer_.set_debug_visitor(spdy_framer_visitor_.get());
  // The headers stream is exempt from connection level flow control.
  DisableConnectionFlowControlForThisStream();
}

QuicHeadersStream::~QuicHeadersStream() {}

size_t QuicHeadersStream::WriteHeaders(QuicStreamId stream_id,
                                       SpdyHeaderBlock headers,
                                       bool fin,
                                       SpdyPriority priority,
                                       QuicAckListenerInterface* ack_listener) {
  SpdyHeadersIR headers_frame(stream_id, std::move(headers));
  headers_frame.set_fin(fin);
  if (session()->perspective() == Perspective::IS_CLIENT) {
    headers_frame.set_has_priority(true);
    headers_frame.set_weight(Spdy3PriorityToHttp2Weight(priority));
  }
  SpdySerializedFrame frame(spdy_framer_.SerializeFrame(headers_frame));
  WriteOrBufferData(StringPiece(frame.data(), frame.size()), false,
                    ack_listener);
  return frame.size();
}

size_t QuicHeadersStream::WritePushPromise(
    QuicStreamId original_stream_id,
    QuicStreamId promised_stream_id,
    SpdyHeaderBlock headers,
    QuicAckListenerInterface* ack_listener) {
  if (session()->perspective() == Perspective::IS_CLIENT) {
    QUIC_BUG << "Client shouldn't send PUSH_PROMISE";
    return 0;
  }

  SpdyPushPromiseIR push_promise(original_stream_id, promised_stream_id,
                                 std::move(headers));

  // PUSH_PROMISE must not be the last frame sent out, at least followed by
  // response headers.
  push_promise.set_fin(false);

  SpdySerializedFrame frame(spdy_framer_.SerializeFrame(push_promise));
  WriteOrBufferData(StringPiece(frame.data(), frame.size()), false,
                    ack_listener);
  return frame.size();
}

void QuicHeadersStream::OnDataAvailable() {
  char buffer[1024];
  struct iovec iov;
  QuicTime timestamp(QuicTime::Zero());
  while (true) {
    iov.iov_base = buffer;
    iov.iov_len = arraysize(buffer);
    if (measure_headers_hol_blocking_time_) {
      if (!sequencer()->GetReadableRegion(&iov, &timestamp)) {
        // No more data to read.
        break;
      }
      DCHECK(timestamp.IsInitialized());
      cur_max_timestamp_ = QuicTime::Max(timestamp, cur_max_timestamp_);
    } else {
      if (sequencer()->GetReadableRegions(&iov, 1) != 1) {
        // No more data to read.
        break;
      }
    }
    if (spdy_framer_.ProcessInput(static_cast<char*>(iov.iov_base),
                                  iov.iov_len) != iov.iov_len) {
      // Error processing data.
      return;
    }
    sequencer()->MarkConsumed(iov.iov_len);
  }
}

void QuicHeadersStream::OnHeaders(SpdyStreamId stream_id,
                                  bool has_priority,
                                  SpdyPriority priority,
                                  bool fin) {
  if (has_priority) {
    if (session()->perspective() == Perspective::IS_CLIENT) {
      CloseConnectionWithDetails(QUIC_INVALID_HEADERS_STREAM_DATA,
                                 "Server must not send priorities.");
      return;
    }
    spdy_session_->OnStreamHeadersPriority(stream_id, priority);
  } else {
    if (session()->perspective() == Perspective::IS_SERVER) {
      CloseConnectionWithDetails(QUIC_INVALID_HEADERS_STREAM_DATA,
                                 "Client must send priorities.");
      return;
    }
  }
  DCHECK_EQ(kInvalidStreamId, stream_id_);
  DCHECK_EQ(kInvalidStreamId, promised_stream_id_);
  stream_id_ = stream_id;
  fin_ = fin;
}

void QuicHeadersStream::OnPushPromise(SpdyStreamId stream_id,
                                      SpdyStreamId promised_stream_id,
                                      bool end) {
  DCHECK_EQ(kInvalidStreamId, stream_id_);
  DCHECK_EQ(kInvalidStreamId, promised_stream_id_);
  stream_id_ = stream_id;
  promised_stream_id_ = promised_stream_id;
}

void QuicHeadersStream::OnControlFrameHeaderData(SpdyStreamId stream_id,
                                                 const char* header_data,
                                                 size_t len) {
  DCHECK_EQ(stream_id_, stream_id);
  if (len == 0) {
    DCHECK_NE(0u, stream_id_);
    DCHECK_NE(0u, frame_len_);
    if (measure_headers_hol_blocking_time_) {
      if (prev_max_timestamp_ > cur_max_timestamp_) {
        // prev_max_timestamp_ > cur_max_timestamp_ implies that
        // headers from lower numbered streams actually came off the
        // wire after headers for the current stream, hence there was
        // HOL blocking.
        QuicTime::Delta delta(prev_max_timestamp_.Subtract(cur_max_timestamp_));
        DVLOG(1) << "stream " << stream_id
                 << ": Net.QuicSession.HeadersHOLBlockedTime "
                 << delta.ToMilliseconds();
        spdy_session_->OnHeadersHeadOfLineBlocking(delta);
      }
      prev_max_timestamp_ = std::max(prev_max_timestamp_, cur_max_timestamp_);
      cur_max_timestamp_ = QuicTime::Zero();
    }
    if (promised_stream_id_ == kInvalidStreamId) {
      spdy_session_->OnStreamHeadersComplete(stream_id_, fin_, frame_len_);
    } else {
      spdy_session_->OnPromiseHeadersComplete(stream_id_, promised_stream_id_,
                                              frame_len_);
    }
    if (uncompressed_frame_len_ != 0) {
      int compression_pct = 100 - (100 * frame_len_) / uncompressed_frame_len_;
      DVLOG(1) << "Net.QuicHpackDecompressionPercentage: " << compression_pct;
      UMA_HISTOGRAM_PERCENTAGE("Net.QuicHpackDecompressionPercentage",
                               compression_pct);
    }
    // Reset state for the next frame.
    promised_stream_id_ = kInvalidStreamId;
    stream_id_ = kInvalidStreamId;
    fin_ = false;
    frame_len_ = 0;
    uncompressed_frame_len_ = 0;
  } else {
    uncompressed_frame_len_ += len;
    if (promised_stream_id_ == kInvalidStreamId) {
      spdy_session_->OnStreamHeaders(stream_id_, StringPiece(header_data, len));
    } else {
      spdy_session_->OnPromiseHeaders(stream_id_,
                                      StringPiece(header_data, len));
    }
  }
}

void QuicHeadersStream::OnHeaderList(const QuicHeaderList& header_list) {
  DVLOG(1) << "Received header list for stream " << stream_id_ << ": "
           << header_list.DebugString();
  if (measure_headers_hol_blocking_time_) {
    if (prev_max_timestamp_ > cur_max_timestamp_) {
      // prev_max_timestamp_ > cur_max_timestamp_ implies that
      // headers from lower numbered streams actually came off the
      // wire after headers for the current stream, hence there was
      // HOL blocking.
      QuicTime::Delta delta = prev_max_timestamp_.Subtract(cur_max_timestamp_);
      DVLOG(1) << "stream " << stream_id_
               << ": Net.QuicSession.HeadersHOLBlockedTime "
               << delta.ToMilliseconds();
      spdy_session_->OnHeadersHeadOfLineBlocking(delta);
    }
    prev_max_timestamp_ = std::max(prev_max_timestamp_, cur_max_timestamp_);
    cur_max_timestamp_ = QuicTime::Zero();
  }
  if (promised_stream_id_ == kInvalidStreamId) {
    spdy_session_->OnStreamHeaderList(stream_id_, fin_, frame_len_,
                                      header_list);
  } else {
    spdy_session_->OnPromiseHeaderList(stream_id_, promised_stream_id_,
                                       frame_len_, header_list);
  }
  // Reset state for the next frame.
  promised_stream_id_ = kInvalidStreamId;
  stream_id_ = kInvalidStreamId;
  fin_ = false;
  frame_len_ = 0;
  uncompressed_frame_len_ = 0;
}

void QuicHeadersStream::OnCompressedFrameSize(size_t frame_len) {
  frame_len_ += frame_len;
}

bool QuicHeadersStream::IsConnected() {
  return session()->connection()->connected();
}

void QuicHeadersStream::DisableHpackDynamicTable() {
  spdy_framer_.UpdateHeaderEncoderTableSize(0);
}

void QuicHeadersStream::SetHpackEncoderDebugVisitor(
    std::unique_ptr<HpackDebugVisitor> visitor) {
  spdy_framer_.SetEncoderHeaderTableDebugVisitor(
      std::unique_ptr<HeaderTableDebugVisitor>(new HeaderTableDebugVisitor(
          session()->connection()->helper()->GetClock(), std::move(visitor))));
}

void QuicHeadersStream::SetHpackDecoderDebugVisitor(
    std::unique_ptr<HpackDebugVisitor> visitor) {
  spdy_framer_.SetDecoderHeaderTableDebugVisitor(
      std::unique_ptr<HeaderTableDebugVisitor>(new HeaderTableDebugVisitor(
          session()->connection()->helper()->GetClock(), std::move(visitor))));
}

void QuicHeadersStream::UpdateHeaderEncoderTableSize(uint32_t value) {
  spdy_framer_.UpdateHeaderEncoderTableSize(value);
}

}  // namespace net
