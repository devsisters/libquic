// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack/hpack_input_stream.h"

#include <algorithm>

#include "base/logging.h"
#include "net/spdy/hpack/hpack_huffman_decoder.h"
#include "net/spdy/spdy_bug_tracker.h"

namespace net {

using base::StringPiece;
using std::string;

HpackInputStream::HpackInputStream(StringPiece buffer)
    : buffer_(buffer),
      bit_offset_(0),
      parsed_bytes_(0),
      parsed_bytes_current_(0),
      need_more_data_(false) {}

HpackInputStream::~HpackInputStream() {}

bool HpackInputStream::HasMoreData() const {
  return !buffer_.empty();
}

bool HpackInputStream::MatchPrefixAndConsume(HpackPrefix prefix) {
  if (buffer_.empty()) {
    need_more_data_ = true;
    return false;
  }

  DCHECK_GT(prefix.bit_size, 0u);
  DCHECK_LE(prefix.bit_size, 8u);

  uint32_t peeked = 0;
  size_t peeked_count = 0;

  if (!PeekBits(&peeked_count, &peeked)) {
    return false;
  }

  if ((peeked >> (32 - prefix.bit_size)) == prefix.bits) {
    ConsumeBits(prefix.bit_size);
    return true;
  }
  return false;
}

bool HpackInputStream::PeekNextOctet(uint8_t* next_octet) {
  if (buffer_.empty()) {
    need_more_data_ = true;
    return false;
  }
  if ((bit_offset_ > 0)) {
    DVLOG(1) << "HpackInputStream::PeekNextOctet bit_offset_=" << bit_offset_;
    return false;
  }

  *next_octet = buffer_[0];
  return true;
}

bool HpackInputStream::DecodeNextOctet(uint8_t* next_octet) {
  if (!PeekNextOctet(next_octet)) {
    return false;
  }

  buffer_.remove_prefix(1);
  parsed_bytes_current_ += 1;
  return true;
}

bool HpackInputStream::DecodeNextUint32(uint32_t* I) {
  size_t N = 8 - bit_offset_;
  DCHECK_GT(N, 0u);
  DCHECK_LE(N, 8u);

  bit_offset_ = 0;

  *I = 0;

  uint8_t next_marker = (1 << N) - 1;
  uint8_t next_octet = 0;
  if (!DecodeNextOctet(&next_octet)) {
    if (!need_more_data_) {
      DVLOG(1) << "HpackInputStream::DecodeNextUint32 initial octet error";
    }
    return false;
  }
  *I = next_octet & next_marker;

  bool has_more = (*I == next_marker);
  size_t shift = 0;
  while (has_more && (shift < 32)) {
    uint8_t next_octet = 0;
    if (!DecodeNextOctet(&next_octet)) {
      if (!need_more_data_) {
        DVLOG(1) << "HpackInputStream::DecodeNextUint32 shift=" << shift;
      }
      return false;
    }
    has_more = (next_octet & 0x80) != 0;
    next_octet &= 0x7f;
    uint32_t addend = next_octet << shift;
    // Check for overflow.
    if ((addend >> shift) != next_octet) {
      DVLOG(1) << "HpackInputStream::DecodeNextUint32 overflow";
      return false;
    }
    *I += addend;
    shift += 7;
  }

  return !has_more;
}

bool HpackInputStream::DecodeNextIdentityString(StringPiece* str) {
  uint32_t size = 0;
  if (!DecodeNextUint32(&size)) {
    return false;
  }

  if (size > buffer_.size()) {
    need_more_data_ = true;
    return false;
  }

  *str = StringPiece(buffer_.data(), size);
  buffer_.remove_prefix(size);
  parsed_bytes_current_ += size;
  return true;
}

bool HpackInputStream::DecodeNextHuffmanString(string* str) {
  uint32_t encoded_size = 0;
  if (!DecodeNextUint32(&encoded_size)) {
    if (!need_more_data_) {
      DVLOG(1) << "HpackInputStream::DecodeNextHuffmanString "
               << "unable to decode size";
    }
    return false;
  }

  if (encoded_size > buffer_.size()) {
    need_more_data_ = true;
    DVLOG(1) << "HpackInputStream::DecodeNextHuffmanString " << encoded_size
             << " > " << buffer_.size();
    return false;
  }

  HpackInputStream bounded_reader(StringPiece(buffer_.data(), encoded_size));
  buffer_.remove_prefix(encoded_size);
  parsed_bytes_current_ += encoded_size;

  return HpackHuffmanDecoder::DecodeString(&bounded_reader, str);
}

bool HpackInputStream::PeekBits(size_t* peeked_count, uint32_t* out) const {
  size_t byte_offset = (bit_offset_ + *peeked_count) / 8;
  size_t bit_offset = (bit_offset_ + *peeked_count) % 8;

  if (*peeked_count >= 32 || byte_offset >= buffer_.size()) {
    return false;
  }
  // We'll read the minimum of the current byte remainder,
  // and the remaining unfilled bits of |out|.
  size_t bits_to_read = std::min(32 - *peeked_count, 8 - bit_offset);

  uint32_t new_bits = static_cast<uint32_t>(buffer_[byte_offset]);
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

std::pair<size_t, uint32_t> HpackInputStream::InitializePeekBits() {
  size_t peeked_count = 0;
  uint32_t bits = 0;
  if (bit_offset_ == 0) {
    switch (buffer_.size()) {
      default:
        DCHECK_LE(4u, buffer_.size());
        bits = static_cast<uint32_t>(static_cast<unsigned char>(buffer_[3]));
        peeked_count += 8;
      /* FALLTHROUGH */
      case 3:
        bits |= (static_cast<uint32_t>(static_cast<unsigned char>(buffer_[2]))
                 << 8);
        peeked_count += 8;
      /* FALLTHROUGH */
      case 2:
        bits |= (static_cast<uint32_t>(static_cast<unsigned char>(buffer_[1]))
                 << 16);
        peeked_count += 8;
      /* FALLTHROUGH */
      case 1:
        bits |= (static_cast<uint32_t>(static_cast<unsigned char>(buffer_[0]))
                 << 24);
        peeked_count += 8;
        break;
      case 0:
        break;
    }
  } else {
    SPDY_BUG << "InitializePeekBits called with non-zero bit_offset_: "
             << bit_offset_;
  }
  return std::make_pair(peeked_count, bits);
}

void HpackInputStream::ConsumeBits(size_t bit_count) {
  size_t byte_count = (bit_offset_ + bit_count) / 8;
  bit_offset_ = (bit_offset_ + bit_count) % 8;
  CHECK_GE(buffer_.size(), byte_count);
  if (bit_offset_ != 0) {
    CHECK_GT(buffer_.size(), 0u);
  }
  buffer_.remove_prefix(byte_count);
  parsed_bytes_current_ += byte_count;
}

void HpackInputStream::ConsumeByteRemainder() {
  if (bit_offset_ != 0) {
    ConsumeBits(8 - bit_offset_);
  }
}

uint32_t HpackInputStream::ParsedBytes() const {
  return parsed_bytes_;
}

bool HpackInputStream::NeedMoreData() const {
  return need_more_data_;
}

void HpackInputStream::MarkCurrentPosition() {
  parsed_bytes_ = parsed_bytes_current_;
}

}  // namespace net
