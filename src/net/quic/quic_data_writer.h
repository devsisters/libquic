// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_DATA_WRITER_H_
#define NET_QUIC_QUIC_DATA_WRITER_H_

#include <string>

#include "base/basictypes.h"
#include "base/logging.h"
#include "base/port.h"
#include "base/strings/string_piece.h"
#include "net/base/int128.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"

namespace net {

// This class provides facilities for packing QUIC data.
//
// The QuicDataWriter supports appending primitive values (int, string, etc)
// to a frame instance.  The QuicDataWriter grows its internal memory buffer
// dynamically to hold the sequence of primitive values.   The internal memory
// buffer is exposed as the "data" of the QuicDataWriter.
class NET_EXPORT_PRIVATE QuicDataWriter {
 public:
  explicit QuicDataWriter(size_t length);

  ~QuicDataWriter();

  // Returns the size of the QuicDataWriter's data.
  size_t length() const { return length_; }

  // Takes the buffer from the QuicDataWriter.
  char* take();

  // Methods for adding to the payload.  These values are appended to the end
  // of the QuicDataWriter payload. Note - binary integers are written in
  // host byte order (little endian) not network byte order (big endian).
  bool WriteUInt8(uint8 value);
  bool WriteUInt16(uint16 value);
  bool WriteUInt32(uint32 value);
  bool WriteUInt48(uint64 value);
  bool WriteUInt64(uint64 value);
  // Write unsigned floating point corresponding to the value. Large values are
  // clamped to the maximum representable (kUFloat16MaxValue). Values that can
  // not be represented directly are rounded down.
  bool WriteUFloat16(uint64 value);
  bool WriteStringPiece16(base::StringPiece val);
  bool WriteIOVector(const IOVector& data);
  bool WriteBytes(const void* data, size_t data_len);
  bool WriteRepeatedByte(uint8 byte, size_t count);
  // Fills the remaining buffer with null characters.
  void WritePadding();

  // Methods for editing the payload at a specific offset, where the
  // offset must be within the writer's capacity.
  // Return true if there is enough space at that offset, false otherwise.
  bool WriteUInt8ToOffset(uint8 value, size_t offset);
  bool WriteUInt32ToOffset(uint32 value, size_t offset);
  bool WriteUInt48ToOffset(uint64 value, size_t offset);

  size_t capacity() const {
    return capacity_;
  }

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
