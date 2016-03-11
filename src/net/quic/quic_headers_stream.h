// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_HEADERS_STREAM_H_
#define NET_QUIC_QUIC_HEADERS_STREAM_H_

#include <stddef.h>

#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/reliable_quic_stream.h"
#include "net/spdy/spdy_framer.h"

namespace net {

class QuicSpdySession;

// Headers in QUIC are sent as HTTP/2 HEADERS or PUSH_PROMISE frames
// over a reserved reliable stream with the id 3.  Each endpoint
// (client and server) will allocate an instance of QuicHeadersStream
// to send and receive headers.
class NET_EXPORT_PRIVATE QuicHeadersStream : public ReliableQuicStream {
 public:
  explicit QuicHeadersStream(QuicSpdySession* session);
  ~QuicHeadersStream() override;

  // Writes |headers| for |stream_id| in an HTTP/2 HEADERS frame to the peer.
  // If |fin| is true, the fin flag will be set on the HEADERS frame.  Returns
  // the size, in bytes, of the resulting HEADERS frame.
  virtual size_t WriteHeaders(QuicStreamId stream_id,
                              const SpdyHeaderBlock& headers,
                              bool fin,
                              SpdyPriority priority,
                              QuicAckListenerInterface* ack_listener);

  // Write |headers| for |promised_stream_id| on |original_stream_id| in a
  // PUSH_PROMISE frame to peer.
  // Return the size, in bytes, of the resulting PUSH_PROMISE frame.
  virtual size_t WritePushPromise(QuicStreamId original_stream_id,
                                  QuicStreamId promised_stream_id,
                                  const SpdyHeaderBlock& headers,
                                  QuicAckListenerInterface* ack_listener);

  // ReliableQuicStream implementation
  void OnDataAvailable() override;

  bool supports_push_promise() { return supports_push_promise_; }

 private:
  class SpdyFramerVisitor;

  // The following methods are called by the SimpleVisitor.

  // Called when a HEADERS frame has been received.
  void OnHeaders(SpdyStreamId stream_id,
                 bool has_priority,
                 SpdyPriority priority,
                 bool fin);

  // Called when a PUSH_PROMISE frame has been received.
  void OnPushPromise(SpdyStreamId stream_id,
                     SpdyStreamId promised_stream_id,
                     bool end);

  // Called when a chunk of header data is available. This is called
  // after OnHeaders.
  // |stream_id| The stream receiving the header data.
  // |header_data| A buffer containing the header data chunk received.
  // |len| The length of the header data buffer. A length of zero indicates
  //       that the header data block has been completely sent.
  void OnControlFrameHeaderData(SpdyStreamId stream_id,
                                const char* header_data,
                                size_t len);

  // Called when the size of the compressed frame payload is available.
  void OnCompressedFrameSize(size_t frame_len);

  // Returns true if the session is still connected.
  bool IsConnected();

  QuicSpdySession* spdy_session_;

  // Data about the stream whose headers are being processed.
  QuicStreamId stream_id_;
  QuicStreamId promised_stream_id_;
  bool fin_;
  size_t frame_len_;

  // Helper variables that cache the corresponding feature flag.
  bool measure_headers_hol_blocking_time_;
  bool supports_push_promise_;

  // Timestamps used to measure HOL blocking, these are recorded by
  // the sequencer approximate to the time of arrival off the wire.
  // |cur_max_timestamp_| tracks the most recent arrival time of
  // frames for current (at the headers stream level) processed
  // stream's headers, and |prev_max_timestamp_| tracks the most
  // recent arrival time of lower numbered streams.
  QuicTime cur_max_timestamp_;
  QuicTime prev_max_timestamp_;

  SpdyFramer spdy_framer_;
  scoped_ptr<SpdyFramerVisitor> spdy_framer_visitor_;

  DISALLOW_COPY_AND_ASSIGN(QuicHeadersStream);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_HEADERS_STREAM_H_
