// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>

#include "base/sys_byteorder.h"
#include "net/spdy/spdy_frame_reader.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

SpdyFrameReader::SpdyFrameReader(const char* data, const size_t len)
    : data_(data),
      len_(len),
      ofs_(0) {
}

bool SpdyFrameReader::ReadUInt8(uint8* result) {
  // Make sure that we have the whole uint8.
  if (!CanRead(1)) {
    OnFailure();
    return false;
  }

  // Read into result.
  *result = *reinterpret_cast<const uint8*>(data_ + ofs_);

  // Iterate.
  ofs_ += 1;

  return true;
}

bool SpdyFrameReader::ReadUInt16(uint16* result) {
  // Make sure that we have the whole uint16.
  if (!CanRead(2)) {
    OnFailure();
    return false;
  }

  // Read into result.
  *result = ntohs(*(reinterpret_cast<const uint16*>(data_ + ofs_)));

  // Iterate.
  ofs_ += 2;

  return true;
}

bool SpdyFrameReader::ReadUInt32(uint32* result) {
  // Make sure that we have the whole uint32.
  if (!CanRead(4)) {
    OnFailure();
    return false;
  }

  // Read into result.
  *result = ntohl(*(reinterpret_cast<const uint32*>(data_ + ofs_)));

  // Iterate.
  ofs_ += 4;

  return true;
}

bool SpdyFrameReader::ReadUInt64(uint64* result) {
  // Make sure that we have the whole uint64.
  if (!CanRead(8)) {
    OnFailure();
    return false;
  }

  // Read into result. Network byte order is big-endian.
  uint64 upper = ntohl(*(reinterpret_cast<const uint32*>(data_ + ofs_)));
  uint64 lower = ntohl(*(reinterpret_cast<const uint32*>(data_ + ofs_ + 4)));
  *result = (upper << 32) + lower;

  // Iterate.
  ofs_ += 8;

  return true;
}

bool SpdyFrameReader::ReadUInt31(uint32* result) {
  bool success = ReadUInt32(result);

  // Zero out highest-order bit.
  if (success) {
    *result &= 0x7fffffff;
  }

  return success;
}

bool SpdyFrameReader::ReadUInt24(uint32* result) {
  // Make sure that we have the whole uint24.
  if (!CanRead(3)) {
    OnFailure();
    return false;
  }

  // Read into result.
  *result = 0;
  memcpy(reinterpret_cast<char*>(result) + 1, data_ + ofs_, 3);
  *result = ntohl(*result);

  // Iterate.
  ofs_ += 3;

  return true;
}

bool SpdyFrameReader::ReadStringPiece16(base::StringPiece* result) {
  // Read resultant length.
  uint16 result_len;
  if (!ReadUInt16(&result_len)) {
    // OnFailure() already called.
    return false;
  }

  // Make sure that we have the whole string.
  if (!CanRead(result_len)) {
    OnFailure();
    return false;
  }

  // Set result.
  result->set(data_ + ofs_, result_len);

  // Iterate.
  ofs_ += result_len;

  return true;
}

bool SpdyFrameReader::ReadStringPiece32(base::StringPiece* result) {
  // Read resultant length.
  uint32 result_len;
  if (!ReadUInt32(&result_len)) {
    // OnFailure() already called.
    return false;
  }

  // Make sure that we have the whole string.
  if (!CanRead(result_len)) {
    OnFailure();
    return false;
  }

  // Set result.
  result->set(data_ + ofs_, result_len);

  // Iterate.
  ofs_ += result_len;

  return true;
}

bool SpdyFrameReader::ReadBytes(void* result, size_t size) {
  // Make sure that we have enough data to read.
  if (!CanRead(size)) {
    OnFailure();
    return false;
  }

  // Read into result.
  memcpy(result, data_ + ofs_, size);

  // Iterate.
  ofs_ += size;

  return true;
}

bool SpdyFrameReader::Seek(size_t size) {
  if (!CanRead(size)) {
    OnFailure();
    return false;
  }

  // Iterate.
  ofs_ += size;

  return true;
}

bool SpdyFrameReader::IsDoneReading() const {
  return len_ == ofs_;
}

bool SpdyFrameReader::CanRead(size_t bytes) const {
  return bytes <= (len_ - ofs_);
}

void SpdyFrameReader::OnFailure() {
  // Set our iterator to the end of the buffer so that further reads fail
  // immediately.
  ofs_ = len_;
}

}  // namespace net
