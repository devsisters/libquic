// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack_input_stream.h"

#include <algorithm>

#include "base/basictypes.h"
#include "base/logging.h"

namespace net {

using base::StringPiece;
using std::string;

HpackInputStream::HpackInputStream(uint32 max_string_literal_size,
                                   StringPiece buffer)
    : max_string_literal_size_(max_string_literal_size),
      buffer_(buffer),
      bit_offset_(0) {}

HpackInputStream::~HpackInputStream() {}

bool HpackInputStream::HasMoreData() const {
  return !buffer_.empty();
}

bool HpackInputStream::MatchPrefixAndConsume(HpackPrefix prefix) {
  DCHECK_GT(prefix.bit_size, 0u);
  DCHECK_LE(prefix.bit_size, 8u);

  uint32 peeked = 0;
  size_t peeked_count = 0;

  if (!PeekBits(&peeked_count, &peeked))
    return false;

  if ((peeked >> (32 - prefix.bit_size)) == prefix.bits) {
    ConsumeBits(prefix.bit_size);
    return true;
  }
  return false;
}

bool HpackInputStream::PeekNextOctet(uint8* next_octet) {
  if ((bit_offset_ > 0) || buffer_.empty())
    return false;

  *next_octet = buffer_[0];
  return true;
}

bool HpackInputStream::DecodeNextOctet(uint8* next_octet) {
  if (!PeekNextOctet(next_octet))
    return false;

  buffer_.remove_prefix(1);
  return true;
}

bool HpackInputStream::DecodeNextUint32(uint32* I) {
  size_t N = 8 - bit_offset_;
  DCHECK_GT(N, 0u);
  DCHECK_LE(N, 8u);

  bit_offset_ = 0;

  *I = 0;

  uint8 next_marker = (1 << N) - 1;
  uint8 next_octet = 0;
  if (!DecodeNextOctet(&next_octet))
    return false;
  *I = next_octet & next_marker;

  bool has_more = (*I == next_marker);
  size_t shift = 0;
  while (has_more && (shift < 32)) {
    uint8 next_octet = 0;
    if (!DecodeNextOctet(&next_octet))
      return false;
    has_more = (next_octet & 0x80) != 0;
    next_octet &= 0x7f;
    uint32 addend = next_octet << shift;
    // Check for overflow.
    if ((addend >> shift) != next_octet) {
      return false;
    }
    *I += addend;
    shift += 7;
  }

  return !has_more;
}

bool HpackInputStream::DecodeNextIdentityString(StringPiece* str) {
  uint32 size = 0;
  if (!DecodeNextUint32(&size))
    return false;

  if (size > max_string_literal_size_)
    return false;

  if (size > buffer_.size())
    return false;

  *str = StringPiece(buffer_.data(), size);
  buffer_.remove_prefix(size);
  return true;
}

bool HpackInputStream::DecodeNextHuffmanString(const HpackHuffmanTable& table,
                                               string* str) {
  uint32 encoded_size = 0;
  if (!DecodeNextUint32(&encoded_size))
    return false;

  if (encoded_size > buffer_.size())
    return false;

  HpackInputStream bounded_reader(
      max_string_literal_size_,
      StringPiece(buffer_.data(), encoded_size));
  buffer_.remove_prefix(encoded_size);

  // HpackHuffmanTable will not decode beyond |max_string_literal_size_|.
  return table.DecodeString(&bounded_reader, max_string_literal_size_, str);
}

bool HpackInputStream::PeekBits(size_t* peeked_count, uint32* out) {
  size_t byte_offset = (bit_offset_ + *peeked_count) / 8;
  size_t bit_offset = (bit_offset_ + *peeked_count) % 8;

  if (*peeked_count >= 32 || byte_offset >= buffer_.size()) {
    return false;
  }
  // We'll read the minimum of the current byte remainder,
  // and the remaining unfilled bits of |out|.
  size_t bits_to_read = std::min(32 - *peeked_count, 8 - bit_offset);

  uint32 new_bits = static_cast<uint32>(buffer_[byte_offset]);
  // Shift byte remainder to most-signifcant bits of |new_bits|.
  // This drops the leading |bit_offset| bits of the byte.
  new_bits = new_bits << (24 + bit_offset);
  // Shift bits to the most-significant open bits of |out|.
  new_bits = new_bits >> *peeked_count;

  CHECK_EQ(*out & new_bits, 0u);
  *out |= new_bits;

  *peeked_count += bits_to_read;
  return true;
}

void HpackInputStream::ConsumeBits(size_t bit_count) {
  size_t byte_count = (bit_offset_ + bit_count) / 8;
  bit_offset_ = (bit_offset_ + bit_count) % 8;
  CHECK_GE(buffer_.size(), byte_count);
  if (bit_offset_ != 0) {
    CHECK_GT(buffer_.size(), 0u);
  }
  buffer_.remove_prefix(byte_count);
}

void HpackInputStream::ConsumeByteRemainder() {
  if (bit_offset_ != 0) {
    ConsumeBits(8 - bit_offset_);
  }
}

}  // namespace net
