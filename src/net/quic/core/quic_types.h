// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_TYPES_H_
#define NET_QUIC_QUIC_TYPES_H_

// This header defines some basic types that don't depend on quic_protocol.h,
// so that classes not directly related to the protocol wire format can avoid
// including quic_protocol.h.

#include <stddef.h>

#include <ostream>

#include "net/base/net_export.h"

namespace net {

// A struct for functions which consume data payloads and fins.
struct NET_EXPORT_PRIVATE QuicConsumedData {
  QuicConsumedData(size_t bytes_consumed, bool fin_consumed);

  // By default, gtest prints the raw bytes of an object. The bool data
  // member causes this object to have padding bytes, which causes the
  // default gtest object printer to read uninitialize memory. So we need
  // to teach gtest how to print this object.
  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicConsumedData& s);

  // How many bytes were consumed.
  size_t bytes_consumed;

  // True if an incoming fin was consumed.
  bool fin_consumed;
};

// QuicAsyncStatus enumerates the possible results of an asynchronous
// operation.
enum QuicAsyncStatus {
  QUIC_SUCCESS = 0,
  QUIC_FAILURE = 1,
  // QUIC_PENDING results from an operation that will occur asynchonously. When
  // the operation is complete, a callback's |Run| method will be called.
  QUIC_PENDING = 2,
};

// TODO(wtc): see if WriteStatus can be replaced by QuicAsyncStatus.
enum WriteStatus {
  WRITE_STATUS_OK,
  WRITE_STATUS_BLOCKED,
  WRITE_STATUS_ERROR,
};

// A struct used to return the result of write calls including either the number
// of bytes written or the error code, depending upon the status.
struct NET_EXPORT_PRIVATE WriteResult {
  WriteResult(WriteStatus status, int bytes_written_or_error_code);
  WriteResult();

  WriteStatus status;
  union {
    int bytes_written;  // only valid when status is WRITE_STATUS_OK
    int error_code;     // only valid when status is WRITE_STATUS_ERROR
  };
};

}  // namespace net

#endif  // NET_QUIC_QUIC_TYPES_H_
