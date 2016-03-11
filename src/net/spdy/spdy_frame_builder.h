// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_FRAME_BUILDER_H_
#define NET_SPDY_SPDY_FRAME_BUILDER_H_

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "base/sys_byteorder.h"
#include "net/base/net_export.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

class SpdyFramer;

// This class provides facilities for basic binary value packing
// into Spdy frames.
//
// The SpdyFrameBuilder supports appending primitive values (int, string, etc)
// to a frame instance.  The SpdyFrameBuilder grows its internal memory buffer
// dynamically to hold the sequence of primitive values.   The internal memory
// buffer is exposed as the "data" of the SpdyFrameBuilder.
class NET_EXPORT_PRIVATE SpdyFrameBuilder {
 public:
  // Initializes a SpdyFrameBuilder with a buffer of given size
  SpdyFrameBuilder(size_t size, SpdyMajorVersion version);

  ~SpdyFrameBuilder();

  // Returns the total size of the SpdyFrameBuilder's data, which may include
  // multiple frames.
  size_t length() const { return offset_ + length_; }

  // Returns a writeable buffer of given size in bytes, to be appended to the
  // currently written frame. Does bounds checking on length but does not
  // increment the underlying iterator. To do so, consumers should subsequently
  // call Seek().
  // In general, consumers should use Write*() calls instead of this.
  // Returns NULL on failure.
  char* GetWritableBuffer(size_t length);

  // Seeks forward by the given number of bytes. Useful in conjunction with
  // GetWriteableBuffer() above.
  bool Seek(size_t length);

  // Populates this frame with a SPDY control frame header using
  // version-specific information from the |framer| and length information from
  // capacity_. The given type must be a control frame type.
  // Used only for SPDY versions <4.
  bool WriteControlFrameHeader(const SpdyFramer& framer,
                               SpdyFrameType type,
                               uint8_t flags);

  // Populates this frame with a SPDY data frame header using version-specific
  // information from the |framer| and length information from capacity_.
  bool WriteDataFrameHeader(const SpdyFramer& framer,
                            SpdyStreamId stream_id,
                            uint8_t flags);

  // Populates this frame with a SPDY4/HTTP2 frame prefix using
  // version-specific information from the |framer| and length information from
  // capacity_. The given type must be a control frame type.
  // Used only for SPDY versions >=4.
  bool BeginNewFrame(const SpdyFramer& framer,
                     SpdyFrameType type,
                     uint8_t flags,
                     SpdyStreamId stream_id);

  // Takes the buffer from the SpdyFrameBuilder.
  SpdyFrame* take() {
    if (version_ == HTTP2) {
      DLOG_IF(DFATAL, SpdyConstants::GetFrameMaximumSize(version_) < length_)
          << "Frame length " << length_
          << " is longer than the maximum allowed length.";
    }
    SpdyFrame* rv = new SpdyFrame(buffer_.release(), length(), true);
    capacity_ = 0;
    length_ = 0;
    offset_ = 0;
    return rv;
  }

  // Methods for adding to the payload.  These values are appended to the end
  // of the SpdyFrameBuilder payload. Note - binary integers are converted from
  // host to network form.
  bool WriteUInt8(uint8_t value) { return WriteBytes(&value, sizeof(value)); }
  bool WriteUInt16(uint16_t value) {
    value = base::HostToNet16(value);
    return WriteBytes(&value, sizeof(value));
  }
  bool WriteUInt24(uint32_t value) {
    value = base::HostToNet32(value);
    return WriteBytes(reinterpret_cast<char*>(&value) + 1,
                      sizeof(value) - 1);
  }
  bool WriteUInt32(uint32_t value) {
    value = base::HostToNet32(value);
    return WriteBytes(&value, sizeof(value));
  }
  bool WriteUInt64(uint64_t value) {
    uint32_t upper = base::HostToNet32(static_cast<uint32_t>(value >> 32));
    uint32_t lower = base::HostToNet32(static_cast<uint32_t>(value));
    return (WriteBytes(&upper, sizeof(upper)) &&
            WriteBytes(&lower, sizeof(lower)));
  }
  bool WriteStringPiece16(const base::StringPiece& value);
  bool WriteStringPiece32(const base::StringPiece& value);
  bool WriteBytes(const void* data, uint32_t data_len);

  // Update (in-place) the length field in the frame being built to reflect the
  // current actual length of bytes written to said frame through this builder.
  // The framer parameter is used to determine version-specific location and
  // size information of the length field to be written, and must be initialized
  // with the correct version for the frame being written.
  bool RewriteLength(const SpdyFramer& framer);

  // Update (in-place) the length field in the frame being built to reflect the
  // given length.
  // The framer parameter is used to determine version-specific location and
  // size information of the length field to be written, and must be initialized
  // with the correct version for the frame being written.
  bool OverwriteLength(const SpdyFramer& framer, size_t length);

  // Update (in-place) the flags field in the frame being built to reflect the
  // given flags value.
  // Used only for SPDY versions >=4.
  bool OverwriteFlags(const SpdyFramer& framer, uint8_t flags);

 private:
  // Checks to make sure that there is an appropriate amount of space for a
  // write of given size, in bytes.
  bool CanWrite(size_t length) const;

  scoped_ptr<char[]> buffer_;
  size_t capacity_;  // Allocation size of payload, set by constructor.
  size_t length_;    // Length of the latest frame in the buffer.
  size_t offset_;    // Position at which the latest frame begins.

  const SpdyMajorVersion version_;
};

}  // namespace net

#endif  // NET_SPDY_SPDY_FRAME_BUILDER_H_
