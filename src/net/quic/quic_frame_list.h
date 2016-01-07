// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_FRAME_LIST_H_
#define NET_QUIC_QUIC_FRAME_LIST_H_

#include <stddef.h>

#include "net/quic/quic_protocol.h"
#include "net/quic/quic_stream_sequencer_buffer_interface.h"

using base::StringPiece;
using std::string;
using std::list;

namespace net {

namespace test {
class QuicStreamSequencerPeer;
}

class NET_EXPORT_PRIVATE QuicFrameList
    : public QuicStreamSequencerBufferInterface {
 public:
  // A contiguous segment received by a QUIC stream.
  struct FrameData {
    FrameData(QuicStreamOffset offset,
              string segment,
              const QuicTime timestamp);

    const QuicStreamOffset offset;
    string segment;
    const QuicTime timestamp;
  };

  explicit QuicFrameList();

  ~QuicFrameList() override;

  //  QuicStreamSequencerBufferInterface implementation
  void Clear() override;
  bool Empty() const override;
  QuicErrorCode OnStreamData(QuicStreamOffset offset,
                             StringPiece data,
                             QuicTime timestamp,
                             size_t* bytes_buffered) override;
  size_t Readv(const struct iovec* iov, size_t iov_len) override;
  int GetReadableRegions(struct iovec* iov, int iov_len) const override;
  bool GetReadableRegion(iovec* iov, QuicTime* timestamp) const override;
  bool MarkConsumed(size_t bytes_used) override;
  size_t FlushBufferedFrames() override;
  bool HasBytesToRead() const override;
  QuicStreamOffset BytesConsumed() const override;
  size_t BytesBuffered() const override;

 private:
  friend class test::QuicStreamSequencerPeer;

  list<FrameData>::iterator FindInsertionPoint(QuicStreamOffset offset,
                                               size_t len);

  bool FrameOverlapsBufferedData(
      QuicStreamOffset offset,
      size_t data_len,
      list<FrameData>::const_iterator insertion_point) const;

  bool IsDuplicate(QuicStreamOffset offset,
                   size_t data_len,
                   list<FrameData>::const_iterator insertion_point) const;

  list<FrameData> frame_list_;

  // Number of bytes in buffer.
  size_t num_bytes_buffered_ = 0;

  QuicStreamOffset total_bytes_read_ = 0;
};

}  // namespace net

#endif  // NET_QUIC_QUIC_FRAME_LIST_H_
