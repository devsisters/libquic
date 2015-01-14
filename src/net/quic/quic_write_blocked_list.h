// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#ifndef NET_QUIC_QUIC_WRITE_BLOCKED_LIST_H_
#define NET_QUIC_QUIC_WRITE_BLOCKED_LIST_H_

#include <set>

#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"
#include "net/spdy/write_blocked_list.h"

namespace net {

// Keeps tracks of the QUIC streams that have data to write, sorted by
// priority.  QUIC stream priority order is:
// Crypto stream > Headers stream > Data streams by requested priority.
class NET_EXPORT_PRIVATE QuicWriteBlockedList {
 private:
  typedef WriteBlockedList<QuicStreamId> QuicWriteBlockedListBase;

 public:
  static const QuicPriority kHighestPriority;
  static const QuicPriority kLowestPriority;

  QuicWriteBlockedList();
  ~QuicWriteBlockedList();

  bool HasWriteBlockedDataStreams() const {
    return base_write_blocked_list_.HasWriteBlockedStreams();
  }

  bool HasWriteBlockedCryptoOrHeadersStream() const {
    return crypto_stream_blocked_ || headers_stream_blocked_;
  }

  size_t NumBlockedStreams() const {
    size_t num_blocked = base_write_blocked_list_.NumBlockedStreams();
    if (crypto_stream_blocked_) {
      ++num_blocked;
    }
    if (headers_stream_blocked_) {
      ++num_blocked;
    }

    return num_blocked;
  }

  QuicStreamId PopFront() {
    if (crypto_stream_blocked_) {
      crypto_stream_blocked_ = false;
      return kCryptoStreamId;
    }

    if (headers_stream_blocked_) {
      headers_stream_blocked_ = false;
      return kHeadersStreamId;
    }

    SpdyPriority priority =
        base_write_blocked_list_.GetHighestPriorityWriteBlockedList();
    QuicStreamId id = base_write_blocked_list_.PopFront(priority);
    blocked_streams_.erase(id);
    return id;
  }

  void PushBack(QuicStreamId stream_id, QuicPriority priority) {
    if (stream_id == kCryptoStreamId) {
      DCHECK_EQ(kHighestPriority, priority);
      // TODO(avd) Add DCHECK(!crypto_stream_blocked_)
      crypto_stream_blocked_ = true;
      return;
    }

    if (stream_id == kHeadersStreamId) {
      DCHECK_EQ(kHighestPriority, priority);
      // TODO(avd) Add DCHECK(!headers_stream_blocked_);
      headers_stream_blocked_ = true;
      return;
    }

    if (blocked_streams_.find(stream_id) != blocked_streams_.end()) {
      DVLOG(1) << "Stream " << stream_id << " already in write blocked list.";
      return;
    }

    base_write_blocked_list_.PushBack(
        stream_id, static_cast<SpdyPriority>(priority));
    blocked_streams_.insert(stream_id);
    return;
  }

  bool crypto_stream_blocked() const { return crypto_stream_blocked_; }
  bool headers_stream_blocked() const { return headers_stream_blocked_; }

 private:
  QuicWriteBlockedListBase base_write_blocked_list_;
  bool crypto_stream_blocked_;
  bool headers_stream_blocked_;

  // Keep track of write blocked streams in a set for faster membership checking
  // than iterating over the base_write_blocked_list_. The contents of this set
  // should mirror the contents of base_write_blocked_list_.
  std::set<QuicStreamId> blocked_streams_;

  DISALLOW_COPY_AND_ASSIGN(QuicWriteBlockedList);
};

}  // namespace net


#endif  // NET_QUIC_QUIC_WRITE_BLOCKED_LIST_H_
