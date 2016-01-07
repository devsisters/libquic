// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_DATA_WRITER_H_
#define NET_QUIC_QUIC_DATA_WRITER_H_

#include <stddef.h>
#include <stdint.h>

#include <cstddef>
#include <string>

#include "base/logging.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/int128.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"

namespace net {

// This class provides facilities for packing QUIC data.
//
// The QuicDataWriter supports appending primitive values (int, string, etc)
// to a frame instance.  The internal memory buffer is exposed as the "data"
// of the QuicDataWriter.
class NET_EXPORT_PRIVATE QuicDataWriter {
 public:
  // Creates a QuicDataWriter where |buffer| is not owned.
  QuicDataWriter(size_t size, char* buffer);

  ~QuicDataWriter();

  // Returns the size of the QuicDataWriter's data.
  size_t length() const { return length_; }

  // Retrieves the buffer from the QuicDataWriter without changing ownership.
  char* data();

  // Methods for adding to the payload.  These values are appended to the end
  // of the QuicDataWriter payload. Note - binary integers are written in
  // host byte order (little endian) not network byte order (big endian).
  bool WriteUInt8(uint8_t value);
  bool WriteUInt16(uint16_t value);
  bool WriteUInt32(uint32_t value);
  bool WriteUInt48(uint64_t value);
  bool WriteUInt64(uint64_t value);
  // Write unsigned floating point corresponding to the value. Large values are
  // clamped to the maximum representable (kUFloat16MaxValue). Values that can
  // not be represented directly are rounded down.
  bool WriteUFloat16(uint64_t value);
  bool WriteStringPiece16(base::StringPiece val);
  bool WriteBytes(const void* data, size_t data_len);
  bool WriteRepeatedByte(uint8_t byte, size_t count);
  // Fills the remaining buffer with null characters.
  void WritePadding();

  size_t capacity() const { return capacity_; }

 private:
  // Returns the location that the data should be written at, or nullptr if
  // there is not enough room. Call EndWrite with the returned offset and the
  // given length to pad out for the next write.
  char* BeginWrite(size_t length);

  char* buffer_;
  size_t capacity_;  // Allocation size of payload (or -1 if buffer is const).
  size_t length_;    // Current length of the buffer.

  DISALLOW_COPY_AND_ASSIGN(QuicDataWriter);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_DATA_WRITER_H_
