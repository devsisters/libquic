// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_types.h"

using std::ostream;

namespace net {

QuicConsumedData::QuicConsumedData(size_t bytes_consumed,
                                   bool fin_consumed)
      : bytes_consumed(bytes_consumed),
        fin_consumed(fin_consumed) {
}

ostream& operator<<(ostream& os, const QuicConsumedData& s) {
  os << "bytes_consumed: " << s.bytes_consumed
     << " fin_consumed: " << s.fin_consumed;
  return os;
}

WriteResult::WriteResult()
    : status(WRITE_STATUS_ERROR),
      bytes_written(0) {
}

WriteResult::WriteResult(WriteStatus status,
                         int bytes_written_or_error_code)
    : status(status),
      bytes_written(bytes_written_or_error_code) {
}

}  // namespace net
