// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_frame_builder.h"

#include <limits>

#include "base/logging.h"
#include "net/spdy/spdy_bug_tracker.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

namespace {

// A special structure for the 8 bit flags and 24 bit length fields.
union FlagsAndLength {
  uint8_t flags[4];  // 8 bits
  uint32_t length;   // 24 bits
};

// Creates a FlagsAndLength.
FlagsAndLength CreateFlagsAndLength(uint8_t flags, size_t length) {
  DCHECK_EQ(0u, length & ~static_cast<size_t>(kLengthMask));
  FlagsAndLength flags_length;
  flags_length.length = base::HostToNet32(static_cast<uint32_t>(length));
  DCHECK_EQ(0, flags & ~kControlFlagsMask);
  flags_length.flags[0] = flags;
  return flags_length;
}

}  // namespace

SpdyFrameBuilder::SpdyFrameBuilder(size_t size, SpdyMajorVersion version)
    : buffer_(new char[size]),
      capacity_(size),
      length_(0),
      offset_(0),
      version_(version) {
}

SpdyFrameBuilder::~SpdyFrameBuilder() {
}

char* SpdyFrameBuilder::GetWritableBuffer(size_t length) {
  if (!CanWrite(length)) {
    return NULL;
  }
  return buffer_.get() + offset_ + length_;
}

bool SpdyFrameBuilder::Seek(size_t length) {
  if (!CanWrite(length)) {
    return false;
  }

  length_ += length;
  return true;
}

bool SpdyFrameBuilder::WriteControlFrameHeader(const SpdyFramer& framer,
                                               SpdyFrameType type,
                                               uint8_t flags) {
  DCHECK_EQ(SPDY3, version_);
  DCHECK(SpdyConstants::IsValidFrameType(
      version_, SpdyConstants::SerializeFrameType(version_, type)));
  bool success = true;
  FlagsAndLength flags_length = CreateFlagsAndLength(
      flags, capacity_ - framer.GetControlFrameHeaderSize());
  success &= WriteUInt16(kControlFlagMask | kSpdy3Version);
  success &= WriteUInt16(
      SpdyConstants::SerializeFrameType(framer.protocol_version(), type));
  success &= WriteBytes(&flags_length, sizeof(flags_length));
  DCHECK_EQ(framer.GetControlFrameHeaderSize(), length());
  return success;
}

bool SpdyFrameBuilder::WriteDataFrameHeader(const SpdyFramer& framer,
                                            SpdyStreamId stream_id,
                                            uint8_t flags) {
  if (version_ == HTTP2) {
    return BeginNewFrame(framer, DATA, flags, stream_id);
  }
  DCHECK_EQ(0u, stream_id & ~kStreamIdMask);
  bool success = true;
  success &= WriteUInt32(stream_id);
  size_t length_field = capacity_ - framer.GetDataFrameMinimumSize();
  DCHECK_EQ(0u, length_field & ~static_cast<size_t>(kLengthMask));
  FlagsAndLength flags_length;
  flags_length.length = base::HostToNet32(static_cast<uint32_t>(length_field));
  DCHECK_EQ(0, flags & ~kDataFlagsMask);
  flags_length.flags[0] = flags;
  success &= WriteBytes(&flags_length, sizeof(flags_length));
  DCHECK_EQ(framer.GetDataFrameMinimumSize(), length());
  return success;
}

bool SpdyFrameBuilder::BeginNewFrame(const SpdyFramer& framer,
                                     SpdyFrameType type,
                                     uint8_t flags,
                                     SpdyStreamId stream_id) {
  DCHECK(SpdyConstants::IsValidFrameType(
      version_, SpdyConstants::SerializeFrameType(version_, type)));
  DCHECK_EQ(0u, stream_id & ~kStreamIdMask);
  DCHECK_EQ(HTTP2, framer.protocol_version());
  bool success = true;
  if (length_ > 0) {
    // Update length field for previous frame.
    OverwriteLength(framer, length_ - framer.GetPrefixLength(type));
    SPDY_BUG_IF(SpdyConstants::GetFrameMaximumSize(version_) < length_)
        << "Frame length  " << length_
        << " is longer than the maximum allowed length.";
  }

  offset_ += length_;
  length_ = 0;

  // Assume all remaining capacity will be used for this frame. If not,
  // the length will get overwritten when we begin the next frame.
  // Don't check for length limits here because this may be larger than the
  // actual frame length.
  success &= WriteUInt24(capacity_ - offset_ - framer.GetPrefixLength(type));
  success &= WriteUInt8(
      SpdyConstants::SerializeFrameType(version_, type));
  success &= WriteUInt8(flags);
  success &= WriteUInt32(stream_id);
  DCHECK_EQ(framer.GetDataFrameMinimumSize(), length_);
  return success;
}

bool SpdyFrameBuilder::WriteStringPiece16(const base::StringPiece& value) {
  if (value.size() > 0xffff) {
    DCHECK(false) << "Tried to write string with length > 16bit.";
    return false;
  }

  if (!WriteUInt16(static_cast<uint16_t>(value.size()))) {
    return false;
  }

  return WriteBytes(value.data(), static_cast<uint16_t>(value.size()));
}

bool SpdyFrameBuilder::WriteStringPiece32(const base::StringPiece& value) {
  if (!WriteUInt32(value.size())) {
    return false;
  }

  return WriteBytes(value.data(), value.size());
}

bool SpdyFrameBuilder::WriteBytes(const void* data, uint32_t data_len) {
  if (!CanWrite(data_len)) {
    return false;
  }

  char* dest = GetWritableBuffer(data_len);
  memcpy(dest, data, data_len);
  Seek(data_len);
  return true;
}

bool SpdyFrameBuilder::RewriteLength(const SpdyFramer& framer) {
  return OverwriteLength(framer,
                         length_ - framer.GetControlFrameHeaderSize());
}

bool SpdyFrameBuilder::OverwriteLength(const SpdyFramer& framer,
                                       size_t length) {
  if (version_ == SPDY3) {
    DCHECK_LE(length,
              SpdyConstants::GetFrameMaximumSize(version_) -
                  framer.GetFrameMinimumSize());
  } else {
    DCHECK_LE(length, SpdyConstants::GetFrameMaximumSize(version_));
  }
  bool success = false;
  const size_t old_length = length_;

  if (version_ == SPDY3) {
    FlagsAndLength flags_length = CreateFlagsAndLength(
        0,  // We're not writing over the flags value anyway.
        length);

    // Write into the correct location by temporarily faking the offset.
    length_ = 5;  // Offset at which the length field occurs.
    success = WriteBytes(reinterpret_cast<char*>(&flags_length) + 1,
                         sizeof(flags_length) - 1);
  } else {
    length_ = 0;
    success = WriteUInt24(length);
  }

  length_ = old_length;
  return success;
}

bool SpdyFrameBuilder::OverwriteFlags(const SpdyFramer& framer, uint8_t flags) {
  DCHECK_EQ(HTTP2, framer.protocol_version());
  bool success = false;
  const size_t old_length = length_;
  // Flags are the fifth octet in the frame prefix.
  length_ = 4;
  success = WriteUInt8(flags);
  length_ = old_length;
  return success;
}

bool SpdyFrameBuilder::CanWrite(size_t length) const {
  if (length > kLengthMask) {
    DCHECK(false);
    return false;
  }

  if (offset_ + length_ + length > capacity_) {
    DCHECK(false);
    return false;
  }

  return true;
}

}  // namespace net
