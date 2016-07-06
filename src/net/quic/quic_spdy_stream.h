// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The base class for streams which deliver data to/from an application.
// In each direction, the data on such a stream first contains compressed
// headers then body data.

#ifndef NET_QUIC_QUIC_SPDY_STREAM_H_
#define NET_QUIC_QUIC_SPDY_STREAM_H_

#include <stddef.h>
#include <sys/types.h>

#include <list>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/iovec.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_export.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_header_list.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_stream_sequencer.h"
#include "net/quic/reliable_quic_stream.h"
#include "net/spdy/spdy_framer.h"

namespace net {

namespace test {
class QuicSpdyStreamPeer;
class ReliableQuicStreamPeer;
}  // namespace test

class QuicSpdySession;

// This is somewhat arbitrary.  It's possible, but unlikely, we will either fail
// to set a priority client-side, or cancel a stream before stripping the
// priority from the wire server-side.  In either case, start out with a
// priority in the middle.
const SpdyPriority kDefaultPriority = 3;

// A QUIC stream that can send and receive HTTP2 (SPDY) headers.
class NET_EXPORT_PRIVATE QuicSpdyStream : public ReliableQuicStream {
 public:
  // Visitor receives callbacks from the stream.
  class NET_EXPORT_PRIVATE Visitor {
   public:
    Visitor() {}

    // Called when the stream is closed.
    virtual void OnClose(QuicSpdyStream* stream) = 0;

    // Allows subclasses to override and do work.
    virtual void OnPromiseHeadersComplete(QuicStreamId promised_id,
                                          size_t frame_len) {}

   protected:
    virtual ~Visitor() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(Visitor);
  };

  QuicSpdyStream(QuicStreamId id, QuicSpdySession* spdy_session);
  ~QuicSpdyStream() override;

  // Override the base class to send QUIC_STREAM_NO_ERROR to the peer
  // when the stream has not received all the data.
  void CloseWriteSide() override;
  void StopReading() override;

  // ReliableQuicStream implementation
  void OnClose() override;

  // Called by the session when decompressed headers data is received
  // for this stream.
  // May be called multiple times, with each call providing additional headers
  // data until OnStreamHeadersComplete is called.
  virtual void OnStreamHeaders(base::StringPiece headers_data);

  // Called by the session when headers with a priority have been received
  // for this stream.  This method will only be called for server streams.
  virtual void OnStreamHeadersPriority(SpdyPriority priority);

  // Called by the session when decompressed headers have been completely
  // delivered to this stream.  If |fin| is true, then this stream
  // should be closed; no more data will be sent by the peer.
  virtual void OnStreamHeadersComplete(bool fin, size_t frame_len);

  // Called by the session when decompressed headers have been completely
  // delivered to this stream.  If |fin| is true, then this stream
  // should be closed; no more data will be sent by the peer.
  virtual void OnStreamHeaderList(bool fin,
                                  size_t frame_len,
                                  const QuicHeaderList& header_list);

  // Called by the session when decompressed PUSH_PROMISE headers data
  // is received for this stream.
  // May be called multiple times, with each call providing additional headers
  // data until OnPromiseHeadersComplete is called.
  virtual void OnPromiseHeaders(base::StringPiece headers_data);

  // Called by the session when decompressed push promise headers have
  // been completely delivered to this stream.
  virtual void OnPromiseHeadersComplete(QuicStreamId promised_id,
                                        size_t frame_len);

  // Called by the session when decompressed push promise headers have
  // been completely delivered to this stream.
  virtual void OnPromiseHeaderList(QuicStreamId promised_id,
                                   size_t frame_len,
                                   const QuicHeaderList& header_list);

  // Override the base class to not discard response when receiving
  // QUIC_STREAM_NO_ERROR on QUIC_VERSION_29 and later versions.
  void OnStreamReset(const QuicRstStreamFrame& frame) override;

  // Writes the headers contained in |header_block| to the dedicated
  // headers stream.
  virtual size_t WriteHeaders(SpdyHeaderBlock header_block,
                              bool fin,
                              QuicAckListenerInterface* ack_notifier_delegate);

  // Sends |data| to the peer, or buffers if it can't be sent immediately.
  void WriteOrBufferBody(const std::string& data,
                         bool fin,
                         QuicAckListenerInterface* ack_notifier_delegate);

  // Writes the trailers contained in |trailer_block| to the dedicated
  // headers stream. Trailers will always have the FIN set.
  virtual size_t WriteTrailers(SpdyHeaderBlock trailer_block,
                               QuicAckListenerInterface* ack_notifier_delegate);

  // Marks |bytes_consumed| of the headers data as consumed.
  void MarkHeadersConsumed(size_t bytes_consumed);

  // Marks |bytes_consumed| of the trailers data as consumed.
  void MarkTrailersConsumed(size_t bytes_consumed);

  // Marks the trailers as consumed.
  void MarkTrailersDelivered();

  // Clears |header_list_|.
  void ConsumeHeaderList();

  // This block of functions wraps the sequencer's functions of the same
  // name.  These methods return uncompressed data until that has
  // been fully processed.  Then they simply delegate to the sequencer.
  virtual size_t Readv(const struct iovec* iov, size_t iov_len);
  virtual int GetReadableRegions(iovec* iov, size_t iov_len) const;
  void MarkConsumed(size_t num_bytes);

  // Returns true if header contains a valid 3-digit status and parse the status
  // code to |status_code|.
  bool ParseHeaderStatusCode(const SpdyHeaderBlock& header,
                             int* status_code) const;

  // Returns true when all data has been read from the peer, including the fin.
  bool IsDoneReading() const;
  bool HasBytesToRead() const;

  void set_visitor(Visitor* visitor) { visitor_ = visitor; }

  bool headers_decompressed() const { return headers_decompressed_; }

  const std::string& decompressed_headers() const {
    return decompressed_headers_;
  }

  const QuicHeaderList& header_list() const { return header_list_; }

  bool trailers_decompressed() const { return trailers_decompressed_; }

  const std::string& decompressed_trailers() const {
    return decompressed_trailers_;
  }

  // Returns whatever trailers have been received for this stream.
  const SpdyHeaderBlock& received_trailers() const {
    return received_trailers_;
  }

  virtual SpdyPriority priority() const;

  // Sets priority_ to priority.  This should only be called before bytes are
  // written to the server.
  void SetPriority(SpdyPriority priority);

  // Called when owning session is getting deleted to avoid subsequent
  // use of the spdy_session_ member.
  void ClearSession();

 protected:
  // Called by OnStreamHeadersComplete depending on which type (initial or
  // trailing) headers are expected next.
  virtual void OnInitialHeadersComplete(bool fin, size_t frame_len);
  virtual void OnTrailingHeadersComplete(bool fin, size_t frame_len);
  virtual void OnInitialHeadersComplete(bool fin,
                                        size_t frame_len,
                                        const QuicHeaderList& header_list);
  virtual void OnTrailingHeadersComplete(bool fin,
                                         size_t frame_len,
                                         const QuicHeaderList& header_list);
  QuicSpdySession* spdy_session() const { return spdy_session_; }
  Visitor* visitor() { return visitor_; }

  // Returns true if headers have been fully read and consumed.
  bool FinishedReadingHeaders() const;

 private:
  friend class test::QuicSpdyStreamPeer;
  friend class test::ReliableQuicStreamPeer;
  friend class QuicStreamUtils;

  // Returns true if trailers have been fully read and consumed.
  bool FinishedReadingTrailers() const;

  QuicSpdySession* spdy_session_;

  Visitor* visitor_;
  // True if the headers have been completely decompressed.
  bool headers_decompressed_;
  // The priority of the stream, once parsed.
  SpdyPriority priority_;
  // Contains a copy of the decompressed headers until they are consumed
  // via ProcessData or Readv.
  std::string decompressed_headers_;
  // Contains a copy of the decompressed header (name, value) pairs until they
  // are consumed via Readv.
  QuicHeaderList header_list_;

  // True if the trailers have been completely decompressed.
  bool trailers_decompressed_;
  // True if the trailers have been consumed.
  bool trailers_delivered_;
  // Contains a copy of the decompressed trailers until they are consumed
  // via ProcessData or Readv.
  std::string decompressed_trailers_;
  // The parsed trailers received from the peer.
  SpdyHeaderBlock received_trailers_;

  DISALLOW_COPY_AND_ASSIGN(QuicSpdyStream);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_SPDY_STREAM_H_
