// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_write_blocked_list.h"

namespace net {

const QuicPriority QuicWriteBlockedList::kHighestPriority =
    static_cast<QuicPriority>(net::kHighestPriority);
const QuicPriority QuicWriteBlockedList::kLowestPriority =
    static_cast<QuicPriority>(net::kLowestPriority);

QuicWriteBlockedList::QuicWriteBlockedList()
    : crypto_stream_blocked_(false),
      headers_stream_blocked_(false) {}

QuicWriteBlockedList::~QuicWriteBlockedList() {}

}  // namespace net
