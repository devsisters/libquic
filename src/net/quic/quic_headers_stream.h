// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_HEADERS_STREAM_H_
#define NET_QUIC_QUIC_HEADERS_STREAM_H_

#include "base/basictypes.h"
#include "base/memory/scoped_ptr.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/reliable_quic_stream.h"
#include "net/spdy/spdy_framer.h"

namespace net {

class QuicSpdySession;

// Headers in QUIC are sent as SPDY SYN_STREAM or SYN_REPLY frames
// over a reserved reliable stream with the id 3.  Each endpoint (client
// and server) will allocate an instance of QuicHeadersStream to send
// and receive headers.
class NET_EXPORT_PRIVATE QuicHeadersStream : public ReliableQuicStream {
 public:
  explicit QuicHeadersStream(QuicSpdySession* session);
  ~QuicHeadersStream() override;

  // Writes |headers| for |stream_id| in a SYN_STREAM or SYN_REPLY
  // frame to the peer.  If |fin| is true, the fin flag will be set on
  // the SPDY frame.  Returns the size, in bytes, of the resulting
  // SPDY frame.
  size_t WriteHeaders(QuicStreamId stream_id,
                      const SpdyHeaderBlock& headers,
                      bool fin,
                      QuicPriority priority,
                      QuicAckListenerInterface* ack_notifier_delegate);

  // ReliableQuicStream implementation
  void OnDataAvailable() override;
  QuicPriority EffectivePriority() const override;

 private:
  class SpdyFramerVisitor;

  // The following methods are called by the SimpleVisitor.

  // Called when a SYN_STREAM frame has been received.
  void OnSynStream(SpdyStreamId stream_id,
                   SpdyPriority priority,
                   bool fin);

  // Called when a SYN_REPLY frame been received.
  void OnSynReply(SpdyStreamId stream_id, bool fin);

  // Called when a chunk of header data is available. This is called
  // after OnSynStream, or OnSynReply.
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
  bool fin_;
  size_t frame_len_;

  // Helper variable that caches the corresponding feature flag.
  bool measure_headers_hol_blocking_time_;

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
