// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_data_reader.h"

#include "net/base/int128.h"
#include "net/quic/quic_protocol.h"

using base::StringPiece;

namespace net {

QuicDataReader::QuicDataReader(const char* data, const size_t len)
    : data_(data), len_(len), pos_(0) {}

bool QuicDataReader::ReadUInt16(uint16_t* result) {
  return ReadBytes(result, sizeof(*result));
}

bool QuicDataReader::ReadUInt32(uint32_t* result) {
  return ReadBytes(result, sizeof(*result));
}

bool QuicDataReader::ReadUInt64(uint64_t* result) {
  return ReadBytes(result, sizeof(*result));
}

bool QuicDataReader::ReadUFloat16(uint64_t* result) {
  uint16_t value;
  if (!ReadUInt16(&value)) {
    return false;
  }

  *result = value;
  if (*result < (1 << kUFloat16MantissaEffectiveBits)) {
    // Fast path: either the value is denormalized (no hidden bit), or
    // normalized (hidden bit set, exponent offset by one) with exponent zero.
    // Zero exponent offset by one sets the bit exactly where the hidden bit is.
    // So in both cases the value encodes itself.
    return true;
  }

  uint16_t exponent =
      value >> kUFloat16MantissaBits;  // No sign extend on uint!
  // After the fast pass, the exponent is at least one (offset by one).
  // Un-offset the exponent.
  --exponent;
  DCHECK_GE(exponent, 1);
  DCHECK_LE(exponent, kUFloat16MaxExponent);
  // Here we need to clear the exponent and set the hidden bit. We have already
  // decremented the exponent, so when we subtract it, it leaves behind the
  // hidden bit.
  *result -= exponent << kUFloat16MantissaBits;
  *result <<= exponent;
  DCHECK_GE(value, 1 << kUFloat16MantissaEffectiveBits);
  DCHECK_LE(value, kUFloat16MaxValue);
  return true;
}

bool QuicDataReader::ReadStringPiece16(StringPiece* result) {
  // Read resultant length.
  uint16_t result_len;
  if (!ReadUInt16(&result_len)) {
    // OnFailure() already called.
    return false;
  }

  return ReadStringPiece(result, result_len);
}

bool QuicDataReader::ReadStringPiece(StringPiece* result, size_t size) {
  // Make sure that we have enough data to read.
  if (!CanRead(size)) {
    OnFailure();
    return false;
  }

  // Set result.
  result->set(data_ + pos_, size);

  // Iterate.
  pos_ += size;

  return true;
}

StringPiece QuicDataReader::ReadRemainingPayload() {
  StringPiece payload = PeekRemainingPayload();
  pos_ = len_;
  return payload;
}

StringPiece QuicDataReader::PeekRemainingPayload() {
  return StringPiece(data_ + pos_, len_ - pos_);
}

bool QuicDataReader::ReadBytes(void* result, size_t size) {
  // Make sure that we have enough data to read.
  if (!CanRead(size)) {
    OnFailure();
    return false;
  }

  // Read into result.
  memcpy(result, data_ + pos_, size);

  // Iterate.
  pos_ += size;

  return true;
}

bool QuicDataReader::IsDoneReading() const {
  return len_ == pos_;
}

size_t QuicDataReader::BytesRemaining() const {
  return len_ - pos_;
}

bool QuicDataReader::CanRead(size_t bytes) const {
  return bytes <= (len_ - pos_);
}

void QuicDataReader::OnFailure() {
  // Set our iterator to the end of the buffer so that further reads fail
  // immediately.
  pos_ = len_;
}

}  // namespace net
