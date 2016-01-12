// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_data_writer.h"

#include <stdint.h>
#include <algorithm>
#include <limits>

using base::StringPiece;
using std::numeric_limits;

namespace net {

QuicDataWriter::QuicDataWriter(size_t size, char* buffer)
    : buffer_(buffer), capacity_(size), length_(0) {}

QuicDataWriter::~QuicDataWriter() {}

char* QuicDataWriter::data() {
  return buffer_;
}

bool QuicDataWriter::WriteUInt8(uint8_t value) {
  return WriteBytes(&value, sizeof(value));
}

bool QuicDataWriter::WriteUInt16(uint16_t value) {
  return WriteBytes(&value, sizeof(value));
}

bool QuicDataWriter::WriteUInt32(uint32_t value) {
  return WriteBytes(&value, sizeof(value));
}

bool QuicDataWriter::WriteUInt48(uint64_t value) {
  uint16_t hi = static_cast<uint16_t>(value >> 32);
  uint32_t lo = static_cast<uint32_t>(value);
  return WriteUInt32(lo) && WriteUInt16(hi);
}

bool QuicDataWriter::WriteUInt64(uint64_t value) {
  return WriteBytes(&value, sizeof(value));
}

bool QuicDataWriter::WriteUFloat16(uint64_t value) {
  uint16_t result;
  if (value < (UINT64_C(1) << kUFloat16MantissaEffectiveBits)) {
    // Fast path: either the value is denormalized, or has exponent zero.
    // Both cases are represented by the value itself.
    result = static_cast<uint16_t>(value);
  } else if (value >= kUFloat16MaxValue) {
    // Value is out of range; clamp it to the maximum representable.
    result = numeric_limits<uint16_t>::max();
  } else {
    // The highest bit is between position 13 and 42 (zero-based), which
    // corresponds to exponent 1-30. In the output, mantissa is from 0 to 10,
    // hidden bit is 11 and exponent is 11 to 15. Shift the highest bit to 11
    // and count the shifts.
    uint16_t exponent = 0;
    for (uint16_t offset = 16; offset > 0; offset /= 2) {
      // Right-shift the value until the highest bit is in position 11.
      // For offset of 16, 8, 4, 2 and 1 (binary search over 1-30),
      // shift if the bit is at or above 11 + offset.
      if (value >= (UINT64_C(1) << (kUFloat16MantissaBits + offset))) {
        exponent += offset;
        value >>= offset;
      }
    }

    DCHECK_GE(exponent, 1);
    DCHECK_LE(exponent, kUFloat16MaxExponent);
    DCHECK_GE(value, UINT64_C(1) << kUFloat16MantissaBits);
    DCHECK_LT(value, UINT64_C(1) << kUFloat16MantissaEffectiveBits);

    // Hidden bit (position 11) is set. We should remove it and increment the
    // exponent. Equivalently, we just add it to the exponent.
    // This hides the bit.
    result = static_cast<uint16_t>(value + (exponent << kUFloat16MantissaBits));
  }

  return WriteBytes(&result, sizeof(result));
}

bool QuicDataWriter::WriteStringPiece16(StringPiece val) {
  if (val.size() > numeric_limits<uint16_t>::max()) {
    return false;
  }
  if (!WriteUInt16(static_cast<uint16_t>(val.size()))) {
    return false;
  }
  return WriteBytes(val.data(), val.size());
}

char* QuicDataWriter::BeginWrite(size_t length) {
  if (length_ > capacity_) {
    return nullptr;
  }

  if (capacity_ - length_ < length) {
    return nullptr;
  }

#ifdef ARCH_CPU_64_BITS
  DCHECK_LE(length, std::numeric_limits<uint32_t>::max());
#endif

  return buffer_ + length_;
}

bool QuicDataWriter::WriteBytes(const void* data, size_t data_len) {
  char* dest = BeginWrite(data_len);
  if (!dest) {
    return false;
  }

  memcpy(dest, data, data_len);

  length_ += data_len;
  return true;
}

bool QuicDataWriter::WriteRepeatedByte(uint8_t byte, size_t count) {
  char* dest = BeginWrite(count);
  if (!dest) {
    return false;
  }

  memset(dest, byte, count);

  length_ += count;
  return true;
}

void QuicDataWriter::WritePadding() {
  DCHECK_LE(length_, capacity_);
  if (length_ > capacity_) {
    return;
  }
  memset(buffer_ + length_, 0x00, capacity_ - length_);
  length_ = capacity_;
}

}  // namespace net
