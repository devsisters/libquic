// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_FRAMER_DECODER_ADAPTER_H_
#define NET_SPDY_SPDY_FRAMER_DECODER_ADAPTER_H_

#include <stddef.h>

#include "base/strings/string_piece.h"
#include "net/spdy/spdy_alt_svc_wire_format.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_headers_handler_interface.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

// Abstract base class for an HTTP/2 decoder to be called from SpdyFramer.
class SpdyFramerDecoderAdapter {
 public:
  SpdyFramerDecoderAdapter();
  virtual ~SpdyFramerDecoderAdapter();

  // Set callbacks to be called from the framer.  A visitor must be set, or
  // else the framer will likely crash.  It is acceptable for the visitor
  // to do nothing.  If this is called multiple times, only the last visitor
  // will be used.
  virtual void set_visitor(SpdyFramerVisitorInterface* visitor);
  SpdyFramerVisitorInterface* visitor() const { return visitor_; }

  // Set debug callbacks to be called from the framer. The debug visitor is
  // completely optional and need not be set in order for normal operation.
  // If this is called multiple times, only the last visitor will be used.
  virtual void set_debug_visitor(
      SpdyFramerDebugVisitorInterface* debug_visitor);
  SpdyFramerDebugVisitorInterface* debug_visitor() const {
    return debug_visitor_;
  }

  // Sets whether or not ProcessInput returns after finishing a frame, or
  // continues processing additional frames. Normally ProcessInput processes
  // all input, but this method enables the caller (and visitor) to work with
  // a single frame at a time (or that portion of the frame which is provided
  // as input). Reset() does not change the value of this flag.
  virtual void set_process_single_input_frame(bool v);
  bool process_single_input_frame() const {
    return process_single_input_frame_;
  }

  // Decode the |len| bytes of encoded HTTP/2 starting at |*data|. Returns the
  // number of bytes consumed. It is safe to pass more bytes in than may be
  // consumed.
  virtual size_t ProcessInput(const char* data, size_t len) = 0;

  // Reset the decoder (used just for tests at this time).
  virtual void Reset() = 0;

  // Current state of the decoder.
  virtual SpdyFramer::SpdyState state() const = 0;

  // Current error code (NO_ERROR if state != ERROR).
  virtual SpdyFramer::SpdyError error_code() const = 0;

  // Did the most recently decoded frame header appear to be the start of an
  // HTTP/1.1 (or earlier) response? Used to detect if a backend/server that
  // we sent a request to, responded with an HTTP/1.1 response?
  virtual bool probable_http_response() const = 0;

 private:
  SpdyFramerVisitorInterface* visitor_ = nullptr;
  SpdyFramerDebugVisitorInterface* debug_visitor_ = nullptr;
  bool process_single_input_frame_ = false;
};

// Create an instance of NestedSpdyFramerDecoder, which implements
// SpdyFramerDecoderAdapter, delegating to a SpdyFramer instance that will
// actually perform the decoding (when requested via ProcessInput).
SpdyFramerDecoderAdapter* CreateNestedSpdyFramerDecoder(SpdyFramer* outer);

// SpdyFramerVisitorInterface::OnError needs the original SpdyFramer* to
// pass to the visitor (really a listener). This implementation takes care of
// that while passing along all other calls unmodified.
class SpdyFramerVisitorAdapter : public SpdyFramerVisitorInterface {
 public:
  SpdyFramerVisitorAdapter(SpdyFramerVisitorInterface* visitor,
                           SpdyFramer* framer)
      : visitor_(visitor), framer_(framer) {}
  ~SpdyFramerVisitorAdapter() override {}
  // The visitor needs the original SpdyFramer, not the SpdyFramerDecoderAdapter
  // instance.
  void OnError(SpdyFramer* framer) override;
  void OnDataFrameHeader(SpdyStreamId stream_id,
                         size_t length,
                         bool fin) override;
  void OnStreamFrameData(SpdyStreamId stream_id,
                         const char* data,
                         size_t len) override;
  void OnStreamEnd(SpdyStreamId stream_id) override;
  void OnStreamPadding(SpdyStreamId stream_id, size_t len) override;
  SpdyHeadersHandlerInterface* OnHeaderFrameStart(
      SpdyStreamId stream_id) override;
  void OnHeaderFrameEnd(SpdyStreamId stream_id, bool end_headers) override;
  bool OnControlFrameHeaderData(SpdyStreamId stream_id,
                                const char* header_data,
                                size_t header_data_len) override;
  void OnSynStream(SpdyStreamId stream_id,
                   SpdyStreamId associated_stream_id,
                   SpdyPriority priority,
                   bool fin,
                   bool unidirectional) override;
  void OnSynReply(SpdyStreamId stream_id, bool fin) override;
  void OnRstStream(SpdyStreamId stream_id, SpdyRstStreamStatus status) override;
  void OnSetting(SpdySettingsIds id, uint8_t flags, uint32_t value) override;
  void OnPing(SpdyPingId unique_id, bool is_ack) override;
  void OnSettings(bool clear_persisted) override;
  void OnSettingsAck() override;
  void OnSettingsEnd() override;
  void OnGoAway(SpdyStreamId last_accepted_stream_id,
                SpdyGoAwayStatus status) override;
  void OnHeaders(SpdyStreamId stream_id,
                 bool has_priority,
                 int weight,
                 SpdyStreamId parent_stream_id,
                 bool exclusive,
                 bool fin,
                 bool end) override;
  void OnWindowUpdate(SpdyStreamId stream_id, int delta_window_size) override;
  bool OnGoAwayFrameData(const char* goaway_data, size_t len) override;
  bool OnRstStreamFrameData(const char* rst_stream_data, size_t len) override;
  void OnBlocked(SpdyStreamId stream_id) override;
  void OnPushPromise(SpdyStreamId stream_id,
                     SpdyStreamId promised_stream_id,
                     bool end) override;
  void OnContinuation(SpdyStreamId stream_id, bool end) override;
  void OnPriority(SpdyStreamId stream_id,
                  SpdyStreamId parent_id,
                  int weight,
                  bool exclusive) override;
  void OnAltSvc(SpdyStreamId stream_id,
                base::StringPiece origin,
                const SpdyAltSvcWireFormat::AlternativeServiceVector&
                    altsvc_vector) override;
  bool OnUnknownFrame(SpdyStreamId stream_id, int frame_type) override;

 protected:
  SpdyFramerVisitorInterface* visitor() const { return visitor_; }
  SpdyFramer* framer() const { return framer_; }

 private:
  SpdyFramerVisitorInterface* const visitor_;
  SpdyFramer* const framer_;
};

}  // namespace net

#endif  // NET_SPDY_SPDY_FRAMER_DECODER_ADAPTER_H_
