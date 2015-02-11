// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_headers_stream.h"

#include "base/strings/stringprintf.h"
#include "net/quic/quic_session.h"

using base::StringPiece;
using std::string;

namespace net {

namespace {

const QuicStreamId kInvalidStreamId = 0;

}  // namespace

// A SpdyFramer visitor which passed SYN_STREAM and SYN_REPLY frames to
// the QuicDataStream, and closes the connection if any unexpected frames
// are received.
class QuicHeadersStream::SpdyFramerVisitor
    : public SpdyFramerVisitorInterface,
      public SpdyFramerDebugVisitorInterface {
 public:
  SpdyFramerVisitor(SpdyMajorVersion spdy_version, QuicHeadersStream* stream)
      : spdy_version_(spdy_version), stream_(stream) {}

  // SpdyFramerVisitorInterface implementation
  void OnSynStream(SpdyStreamId stream_id,
                   SpdyStreamId associated_stream_id,
                   SpdyPriority priority,
                   bool fin,
                   bool unidirectional) override {
    if (spdy_version_ != SPDY3) {
      CloseConnection("SPDY SYN_STREAM frame received.");
      return;
    }

    if (!stream_->IsConnected()) {
      return;
    }

    if (associated_stream_id != 0) {
      CloseConnection("associated_stream_id != 0");
      return;
    }

    if (unidirectional != 0) {
      CloseConnection("unidirectional != 0");
      return;
    }

    stream_->OnSynStream(stream_id, priority, fin);
  }

  void OnSynReply(SpdyStreamId stream_id, bool fin) override {
    if (spdy_version_ != SPDY3) {
      CloseConnection("SPDY SYN_REPLY frame received.");
      return;
    }

    if (!stream_->IsConnected()) {
      return;
    }

    stream_->OnSynReply(stream_id, fin);
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
                         size_t len,
                         bool fin) override {
    if (fin && len == 0) {
      // The framer invokes OnStreamFrameData with zero-length data and
      // fin = true after processing a SYN_STREAM or SYN_REPLY frame
      // that had the fin bit set.
      return;
    }
    CloseConnection("SPDY DATA frame received.");
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

  void OnSetting(SpdySettingsIds id, uint8 flags, uint32 value) override {
    CloseConnection("SPDY SETTINGS frame received.");
  }

  void OnSettingsAck() override {
    CloseConnection("SPDY SETTINGS frame received.");
  }

  void OnSettingsEnd() override {
    CloseConnection("SPDY SETTINGS frame received.");
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
                 SpdyPriority priority,
                 bool fin,
                 bool end) override {
    if (spdy_version_ == SPDY3) {
      CloseConnection("SPDY HEADERS frame received.");
      return;
    }
    if (!stream_->IsConnected()) {
      return;
    }
    if (has_priority) {
      stream_->OnSynStream(stream_id, priority, fin);
    } else {
      stream_->OnSynReply(stream_id, fin);
    }
  }

  void OnWindowUpdate(SpdyStreamId stream_id,
                      uint32 delta_window_size) override {
    CloseConnection("SPDY WINDOW_UPDATE frame received.");
  }

  void OnPushPromise(SpdyStreamId stream_id,
                     SpdyStreamId promised_stream_id,
                     bool end) override {
    LOG(DFATAL) << "PUSH_PROMISE frame received from a SPDY/3 framer";
    CloseConnection("SPDY PUSH_PROMISE frame received.");
  }

  void OnContinuation(SpdyStreamId stream_id, bool end) override {
    if (spdy_version_ == SPDY3) {
      LOG(DFATAL) << "CONTINUATION frame received from a SPDY/3 framer";
      CloseConnection("SPDY CONTINUATION frame received.");
    }
  }

  bool OnUnknownFrame(SpdyStreamId stream_id, int frame_type) override {
    CloseConnection("Unknown frame type received.");
    return false;
  }

  // SpdyFramerDebugVisitorInterface implementation
  void OnSendCompressedFrame(SpdyStreamId stream_id,
                             SpdyFrameType type,
                             size_t payload_len,
                             size_t frame_len) override {}

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
      stream_->CloseConnectionWithDetails(
          QUIC_INVALID_HEADERS_STREAM_DATA, details);
    }
  }

 private:
  SpdyMajorVersion spdy_version_;
  QuicHeadersStream* stream_;

  DISALLOW_COPY_AND_ASSIGN(SpdyFramerVisitor);
};

QuicHeadersStream::QuicHeadersStream(QuicSession* session)
    : ReliableQuicStream(kHeadersStreamId, session),
      stream_id_(kInvalidStreamId),
      fin_(false),
      frame_len_(0) {
  InitializeFramer(session->connection()->version());
  // The headers stream is exempt from connection level flow control.
  DisableConnectionFlowControlForThisStream();
}

QuicHeadersStream::~QuicHeadersStream() {}

size_t QuicHeadersStream::WriteHeaders(
    QuicStreamId stream_id,
    const SpdyHeaderBlock& headers,
    bool fin,
    QuicPriority priority,
    QuicAckNotifier::DelegateInterface* ack_notifier_delegate) {
  scoped_ptr<SpdySerializedFrame> frame;
  if (spdy_framer_->protocol_version() == SPDY3) {
    if (session()->is_server()) {
      SpdySynReplyIR syn_reply(stream_id);
      syn_reply.set_name_value_block(headers);
      syn_reply.set_fin(fin);
      frame.reset(spdy_framer_->SerializeFrame(syn_reply));
    } else {
      SpdySynStreamIR syn_stream(stream_id);
      syn_stream.set_name_value_block(headers);
      syn_stream.set_fin(fin);
      syn_stream.set_priority(priority);
      frame.reset(spdy_framer_->SerializeFrame(syn_stream));
    }
  } else {
    SpdyHeadersIR headers_frame(stream_id);
    headers_frame.set_name_value_block(headers);
    headers_frame.set_fin(fin);
    if (!session()->is_server()) {
      headers_frame.set_has_priority(true);
      headers_frame.set_priority(priority);
    }
    frame.reset(spdy_framer_->SerializeFrame(headers_frame));
  }
  WriteOrBufferData(StringPiece(frame->data(), frame->size()), false,
                    ack_notifier_delegate);
  return frame->size();
}

uint32 QuicHeadersStream::ProcessRawData(const char* data,
                                         uint32 data_len) {
  return spdy_framer_->ProcessInput(data, data_len);
}

QuicPriority QuicHeadersStream::EffectivePriority() const { return 0; }

void QuicHeadersStream::OnSuccessfulVersionNegotiation(QuicVersion version) {
  InitializeFramer(version);
}

void QuicHeadersStream::InitializeFramer(QuicVersion version) {
  SpdyMajorVersion spdy_version = version > QUIC_VERSION_23 ? SPDY4 : SPDY3;
  if (spdy_framer_.get() != nullptr &&
      spdy_framer_->protocol_version() == spdy_version) {
    return;
  }
  spdy_framer_.reset(new SpdyFramer(spdy_version));
  spdy_framer_visitor_.reset(new SpdyFramerVisitor(spdy_version, this));
  spdy_framer_->set_visitor(spdy_framer_visitor_.get());
  spdy_framer_->set_debug_visitor(spdy_framer_visitor_.get());
}

void QuicHeadersStream::OnSynStream(SpdyStreamId stream_id,
                                    SpdyPriority priority,
                                    bool fin) {
  if (!session()->is_server()) {
    CloseConnectionWithDetails(
        QUIC_INVALID_HEADERS_STREAM_DATA,
        "SPDY SYN_STREAM frame received at the client");
    return;
  }
  DCHECK_EQ(kInvalidStreamId, stream_id_);
  stream_id_ = stream_id;
  fin_ = fin;
  session()->OnStreamHeadersPriority(stream_id, priority);
}

void QuicHeadersStream::OnSynReply(SpdyStreamId stream_id, bool fin) {
  if (session()->is_server()) {
    CloseConnectionWithDetails(
        QUIC_INVALID_HEADERS_STREAM_DATA,
        "SPDY SYN_REPLY frame received at the server");
    return;
  }
  DCHECK_EQ(kInvalidStreamId, stream_id_);
  stream_id_ = stream_id;
  fin_ = fin;
}

void QuicHeadersStream::OnControlFrameHeaderData(SpdyStreamId stream_id,
                                                 const char* header_data,
                                                 size_t len) {
  DCHECK_EQ(stream_id_, stream_id);
  if (len == 0) {
    DCHECK_NE(0u, stream_id_);
    DCHECK_NE(0u, frame_len_);
    session()->OnStreamHeadersComplete(stream_id_, fin_, frame_len_);
    // Reset state for the next frame.
    stream_id_ = kInvalidStreamId;
    fin_ = false;
    frame_len_ = 0;
  } else {
    session()->OnStreamHeaders(stream_id_, StringPiece(header_data, len));
  }
}

void QuicHeadersStream::OnCompressedFrameSize(size_t frame_len) {
  if (spdy_framer_->protocol_version() == SPDY3) {
    // SPDY/3 headers always fit into a single frame, so the previous headers
    // should be completely processed when a new frame is received.
    DCHECK_EQ(kInvalidStreamId, stream_id_);
    DCHECK_EQ(0u, frame_len_);
  }
  frame_len_ += frame_len;
}

bool QuicHeadersStream::IsConnected() {
  return session()->connection()->connected();
}

}  // namespace net
