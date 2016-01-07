// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_STREAM_SEQUENCER_BUFFER_INTERFACE_H_
#define NET_QUIC_QUIC_STREAM_SEQUENCER_BUFFER_INTERFACE_H_

#include <stddef.h>

#include "net/quic/quic_protocol.h"

using base::StringPiece;

namespace net {

// The QuicStreamSequencer uses an implementation of this interface to store
// received data.
class NET_EXPORT_PRIVATE QuicStreamSequencerBufferInterface {
 public:
  virtual ~QuicStreamSequencerBufferInterface() {}

  // Free the space used to buffer data.
  virtual void Clear() = 0;

  // Returns true if there is nothing to read in this buffer.
  virtual bool Empty() const = 0;

  // Called to buffer new data received for this stream.  If the data was
  // successfully buffered, returns QUIC_NO_ERROR and stores the number of
  // bytes buffered in |bytes_buffered|. Returns an error otherwise.
  // |timestamp| is the time the data arrived.
  virtual QuicErrorCode OnStreamData(QuicStreamOffset offset,
                                     StringPiece data,
                                     QuicTime timestamp,
                                     size_t* bytes_buffered) = 0;

  // Reads from this buffer into given iovec array, up to number of iov_len
  // iovec objects and returns the number of bytes read.
  virtual size_t Readv(const struct iovec* iov, size_t iov_len) = 0;

  // Returns the readable region of valid data in iovec format. The readable
  // region is the buffer region where there is valid data not yet read by
  // client.
  // Returns the number of iovec entries in |iov| which were populated.
  // If the region is empty, one iovec entry with 0 length
  // is returned, and the function returns 0. If there are more readable
  // regions than iov_size, the function only processes the first
  // iov_size of them.
  virtual int GetReadableRegions(struct iovec* iov, int iov_len) const = 0;

  // Fills in one iovec with data which all arrived at the same time from the
  // next readable region.
  // Populates |timestamp| with the time that this data arrived.
  // Returns false if there is no readable region available.
  virtual bool GetReadableRegion(iovec* iov, QuicTime* timestamp) const = 0;

  // Called after GetReadableRegions() to free up |bytes_used| space if these
  // bytes are processed.
  // Pre-requisite: bytes_used <= available bytes to read.
  virtual bool MarkConsumed(size_t bytes_used) = 0;

  // Deletes and records as consumed any buffered data and clear the buffer.
  // (To be called only after sequencer's StopReading has been called.)
  virtual size_t FlushBufferedFrames() = 0;

  // Whether there are bytes can be read out.
  virtual bool HasBytesToRead() const = 0;

  // Count how many bytes have been consumed (read out of buffer).
  virtual QuicStreamOffset BytesConsumed() const = 0;

  // Count how many bytes are in buffer at this moment.
  virtual size_t BytesBuffered() const = 0;
};

}  // namespace net

#endif  // NET_QUIC_QUIC_STREAM_SEQUENCER_BUFFER_INTERFACE_H_
