// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_HEADER_LIST_H_
#define NET_QUIC_QUIC_HEADER_LIST_H_

#include <deque>
#include <functional>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_headers_handler_interface.h"

namespace net {

// A simple class that accumulates header pairs
class NET_EXPORT_PRIVATE QuicHeaderList : public SpdyHeadersHandlerInterface {
 public:
  typedef std::deque<std::pair<std::string, std::string>> ListType;
  typedef ListType::const_iterator const_iterator;

  QuicHeaderList();
  QuicHeaderList(QuicHeaderList&& other);
  QuicHeaderList(const QuicHeaderList& other);
  QuicHeaderList& operator=(QuicHeaderList&& other);
  QuicHeaderList& operator=(const QuicHeaderList& other);
  ~QuicHeaderList() override;

  // From SpdyHeadersHandlerInteface.
  void OnHeaderBlockStart() override;
  void OnHeader(base::StringPiece name, base::StringPiece value) override;
  void OnHeaderBlockEnd(size_t uncompressed_header_bytes) override;

  void Clear();

  const_iterator begin() const { return header_list_.begin(); }
  const_iterator end() const { return header_list_.end(); }

  bool empty() const { return header_list_.empty(); }
  size_t uncompressed_header_bytes() const {
    return uncompressed_header_bytes_;
  }

  std::string DebugString() const;

 private:
  std::deque<std::pair<std::string, std::string>> header_list_;
  size_t uncompressed_header_bytes_;
};

}  // namespace net

#endif  // NET_QUIC_QUIC_HEADER_LIST_H_
