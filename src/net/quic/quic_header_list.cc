// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_header_list.h"

using std::string;

namespace net {

QuicHeaderList::QuicHeaderList() : uncompressed_header_bytes_(0) {}

QuicHeaderList::QuicHeaderList(QuicHeaderList&& other) = default;

QuicHeaderList::QuicHeaderList(const QuicHeaderList& other) = default;

QuicHeaderList& QuicHeaderList::operator=(const QuicHeaderList& other) =
    default;

QuicHeaderList& QuicHeaderList::operator=(QuicHeaderList&& other) = default;

QuicHeaderList::~QuicHeaderList() {}

void QuicHeaderList::OnHeaderBlockStart() {
  QUIC_BUG_IF(uncompressed_header_bytes_ != 0)
      << "OnHeaderBlockStart called more than once!";
}

void QuicHeaderList::OnHeader(base::StringPiece name, base::StringPiece value) {
  header_list_.emplace_back(name.as_string(), value.as_string());
}

void QuicHeaderList::OnHeaderBlockEnd(size_t uncompressed_header_bytes) {
  uncompressed_header_bytes_ = uncompressed_header_bytes;
}

void QuicHeaderList::Clear() {
  header_list_.clear();
  uncompressed_header_bytes_ = 0;
}

string QuicHeaderList::DebugString() const {
  string s = "{ ";
  for (const auto& p : *this) {
    s.append(p.first + "=" + p.second + ", ");
  }
  s.append("}");
  return s;
}

}  // namespace net
