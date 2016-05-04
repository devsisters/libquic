// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_SPDY_SESSION_H_
#define NET_QUIC_QUIC_SPDY_SESSION_H_

#include <stddef.h>

#include <memory>

#include "base/macros.h"
#include "net/quic/quic_header_list.h"
#include "net/quic/quic_headers_stream.h"
#include "net/quic/quic_session.h"
#include "net/quic/quic_spdy_stream.h"

namespace net {

namespace test {
class QuicSpdySessionPeer;
}  // namespace test

// A QUIC session with a headers stream.
class NET_EXPORT_PRIVATE QuicSpdySession : public QuicSession {
 public:
  QuicSpdySession(QuicConnection* connection, const QuicConfig& config);

  ~QuicSpdySession() override;

  void Initialize() override;

  // Called by |headers_stream_| when headers have been received for a stream.
  virtual void OnStreamHeaders(QuicStreamId stream_id,
                               base::StringPiece headers_data);
  // Called by |headers_stream_| when headers with a priority have been
  // received for this stream.  This method will only be called for server
  // streams.
  virtual void OnStreamHeadersPriority(QuicStreamId stream_id,
                                       SpdyPriority priority);
  // Called by |headers_stream_| when headers have been completely received
  // for a stream.  |fin| will be true if the fin flag was set in the headers
  // frame.
  virtual void OnStreamHeadersComplete(QuicStreamId stream_id,
                                       bool fin,
                                       size_t frame_len);

  // Called by |headers_stream_| when headers have been completely received
  // for a stream.  |fin| will be true if the fin flag was set in the headers
  // frame.
  virtual void OnStreamHeaderList(QuicStreamId stream_id,
                                  bool fin,
                                  size_t frame_len,
                                  const QuicHeaderList& header_list);

  // Called by |headers_stream_| when push promise headers have been
  // received for a stream.
  virtual void OnPromiseHeaders(QuicStreamId stream_id,
                                base::StringPiece headers_data);

  // Called by |headers_stream_| when push promise headers have been
  // completely received.  |fin| will be true if the fin flag was set
  // in the headers.
  virtual void OnPromiseHeadersComplete(QuicStreamId stream_id,
                                        QuicStreamId promised_stream_id,
                                        size_t frame_len);

  // Called by |headers_stream_| when push promise headers have been
  // completely received.  |fin| will be true if the fin flag was set
  // in the headers.
  virtual void OnPromiseHeaderList(QuicStreamId stream_id,
                                   QuicStreamId promised_stream_id,
                                   size_t frame_len,
                                   const QuicHeaderList& header_list);

  // Writes |headers| for the stream |id| to the dedicated headers stream.
  // If |fin| is true, then no more data will be sent for the stream |id|.
  // If provided, |ack_notifier_delegate| will be registered to be notified when
  // we have seen ACKs for all packets resulting from this call.
  virtual size_t WriteHeaders(QuicStreamId id,
                              const SpdyHeaderBlock& headers,
                              bool fin,
                              SpdyPriority priority,
                              QuicAckListenerInterface* ack_notifier_delegate);

  QuicHeadersStream* headers_stream() { return headers_stream_.get(); }

  // Called when Head of Line Blocking happens in the headers stream.
  // |delta| indicates how long that piece of data has been blocked.
  virtual void OnHeadersHeadOfLineBlocking(QuicTime::Delta delta);

  // Called by the stream on creation to set priority in the write blocked list.
  void RegisterStreamPriority(QuicStreamId id, SpdyPriority priority);
  // Called by the stream on deletion to clear priority crom the write blocked
  // list.
  void UnregisterStreamPriority(QuicStreamId id);
  // Called by the stream on SetPriority to update priority on the write blocked
  // list.
  void UpdateStreamPriority(QuicStreamId id, SpdyPriority new_priority);

  void OnConfigNegotiated() override;

 protected:
  // Override CreateIncomingDynamicStream() and CreateOutgoingDynamicStream()
  // with QuicSpdyStream return type to make sure that all data streams are
  // QuicSpdyStreams.
  QuicSpdyStream* CreateIncomingDynamicStream(QuicStreamId id) override = 0;
  QuicSpdyStream* CreateOutgoingDynamicStream(SpdyPriority priority) override =
      0;

  QuicSpdyStream* GetSpdyDataStream(const QuicStreamId stream_id);

  // If an incoming stream can be created, return true.
  virtual bool ShouldCreateIncomingDynamicStream(QuicStreamId id) = 0;

  // If an outgoing stream can be created, return true.
  virtual bool ShouldCreateOutgoingDynamicStream() = 0;

 private:
  friend class test::QuicSpdySessionPeer;

  std::unique_ptr<QuicHeadersStream> headers_stream_;

  DISALLOW_COPY_AND_ASSIGN(QuicSpdySession);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_SPDY_SESSION_H_
