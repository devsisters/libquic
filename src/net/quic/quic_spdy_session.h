// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_SPDY_SESSION_H_
#define NET_QUIC_QUIC_SPDY_SESSION_H_

#include "base/basictypes.h"
#include "base/memory/scoped_ptr.h"
#include "net/quic/quic_data_stream.h"
#include "net/quic/quic_headers_stream.h"
#include "net/quic/quic_session.h"

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
                               StringPiece headers_data);
  // Called by |headers_stream_| when headers with a priority have been
  // received for this stream.  This method will only be called for server
  // streams.
  virtual void OnStreamHeadersPriority(QuicStreamId stream_id,
                                       QuicPriority priority);
  // Called by |headers_stream_| when headers have been completely received
  // for a stream.  |fin| will be true if the fin flag was set in the headers
  // frame.
  virtual void OnStreamHeadersComplete(QuicStreamId stream_id,
                                       bool fin,
                                       size_t frame_len);

  // Writes |headers| for the stream |id| to the dedicated headers stream.
  // If |fin| is true, then no more data will be sent for the stream |id|.
  // If provided, |ack_notifier_delegate| will be registered to be notified when
  // we have seen ACKs for all packets resulting from this call.
  size_t WriteHeaders(
      QuicStreamId id,
      const SpdyHeaderBlock& headers,
      bool fin,
      QuicPriority priority,
      QuicAckNotifier::DelegateInterface* ack_notifier_delegate);

  QuicHeadersStream* headers_stream() { return headers_stream_.get(); }

 protected:
  // Override CreateIncomingDynamicStream() and CreateOutgoingDynamicStream()
  // with QuicDataStream return type to make sure that all data streams are
  // QuicDataStreams.
  QuicDataStream* CreateIncomingDynamicStream(QuicStreamId id) override = 0;
  QuicDataStream* CreateOutgoingDynamicStream() override = 0;

  QuicDataStream* GetSpdyDataStream(const QuicStreamId stream_id);

 private:
  friend class test::QuicSpdySessionPeer;

  scoped_ptr<QuicHeadersStream> headers_stream_;

  DISALLOW_COPY_AND_ASSIGN(QuicSpdySession);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_SPDY_SESSION_H_
