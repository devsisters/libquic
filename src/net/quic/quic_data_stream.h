// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The base class for streams which deliver data to/from an application.
// In each direction, the data on such a stream first contains compressed
// headers then body data.

#ifndef NET_QUIC_QUIC_DATA_STREAM_H_
#define NET_QUIC_QUIC_DATA_STREAM_H_

#include <sys/types.h>

#include <list>
#include <string>

#include "base/basictypes.h"
#include "base/strings/string_piece.h"
#include "net/base/iovec.h"
#include "net/base/net_export.h"
#include "net/quic/quic_ack_notifier.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_stream_sequencer.h"
#include "net/quic/reliable_quic_stream.h"
#include "net/spdy/spdy_framer.h"

namespace net {

namespace test {
class QuicDataStreamPeer;
class ReliableQuicStreamPeer;
}  // namespace test

class IPEndPoint;
class QuicSession;
class SSLInfo;

// All this does right now is send data to subclasses via the sequencer.
class NET_EXPORT_PRIVATE QuicDataStream : public ReliableQuicStream {
 public:
  // Visitor receives callbacks from the stream.
  class Visitor {
   public:
    Visitor() {}

    // Called when the stream is closed.
    virtual void OnClose(QuicDataStream* stream) = 0;

   protected:
    virtual ~Visitor() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(Visitor);
  };

  QuicDataStream(QuicStreamId id, QuicSession* session);

  ~QuicDataStream() override;

  // ReliableQuicStream implementation
  void OnClose() override;
  uint32 ProcessRawData(const char* data, uint32 data_len) override;
  // By default, this is the same as priority(), however it allows streams
  // to temporarily alter effective priority.   For example if a SPDY stream has
  // compressed but not written headers it can write the headers with a higher
  // priority.
  QuicPriority EffectivePriority() const override;

  // Overridden by subclasses to process data.  The headers will be delivered
  // via OnStreamHeaders, so only data will be delivered through this method.
  virtual uint32 ProcessData(const char* data, uint32 data_len) = 0;

  // Called by the session when decompressed headers data is received
  // for this stream.
  // May be called multiple times, with each call providing additional headers
  // data until OnStreamHeadersComplete is called.
  virtual void OnStreamHeaders(base::StringPiece headers_data);

  // Called by the session when headers with a priority have been received
  // for this stream.  This method will only be called for server streams.
  virtual void OnStreamHeadersPriority(QuicPriority priority);

  // Called by the session when decompressed headers have been completely
  // delilvered to this stream.  If |fin| is true, then this stream
  // should be closed; no more data will be sent by the peer.
  virtual void OnStreamHeadersComplete(bool fin, size_t frame_len);

  // Writes the headers contained in |header_block| to the dedicated
  // headers stream.
  virtual size_t WriteHeaders(
      const SpdyHeaderBlock& header_block,
      bool fin,
      QuicAckNotifier::DelegateInterface* ack_notifier_delegate);

  // This block of functions wraps the sequencer's functions of the same
  // name.  These methods return uncompressed data until that has
  // been fully processed.  Then they simply delegate to the sequencer.
  virtual size_t Readv(const struct iovec* iov, size_t iov_len);
  virtual int GetReadableRegions(iovec* iov, size_t iov_len);
  // Returns true when all data has been read from the peer, including the fin.
  virtual bool IsDoneReading() const;
  virtual bool HasBytesToRead() const;

  void set_visitor(Visitor* visitor) { visitor_ = visitor; }

  bool headers_decompressed() const { return headers_decompressed_; }

  const IPEndPoint& GetPeerAddress();

  // Gets the SSL connection information.
  bool GetSSLInfo(SSLInfo* ssl_info);

 protected:
  // Sets priority_ to priority.  This should only be called before bytes are
  // written to the server.
  void set_priority(QuicPriority priority);
  // This is protected because external classes should use EffectivePriority
  // instead.
  QuicPriority priority() const { return priority_; }

 private:
  friend class test::QuicDataStreamPeer;
  friend class test::ReliableQuicStreamPeer;
  friend class QuicStreamUtils;

  uint32 ProcessHeaderData();

  bool FinishedReadingHeaders();

  Visitor* visitor_;
  // True if the headers have been completely decompresssed.
  bool headers_decompressed_;
  // The priority of the stream, once parsed.
  QuicPriority priority_;
  // Contains a copy of the decompressed headers until they are consumed
  // via ProcessData or Readv.
  std::string decompressed_headers_;

  DISALLOW_COPY_AND_ASSIGN(QuicDataStream);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_DATA_STREAM_H_
