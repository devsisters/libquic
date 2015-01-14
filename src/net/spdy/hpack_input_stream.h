// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_INPUT_STREAM_H_
#define NET_SPDY_HPACK_INPUT_STREAM_H_

#include <string>

#include "base/basictypes.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/spdy/hpack_constants.h"
#include "net/spdy/hpack_huffman_table.h"

// All section references below are to
// http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-08

namespace net {

// An HpackInputStream handles all the low-level details of decoding
// header fields.
class NET_EXPORT_PRIVATE HpackInputStream {
 public:
  // |max_string_literal_size| is the largest that any one string
  // literal (header name or header value) can be.
  HpackInputStream(uint32 max_string_literal_size, base::StringPiece buffer);
  ~HpackInputStream();

  // Returns whether or not there is more data to process.
  bool HasMoreData() const;

  // If the next bits of input match |prefix|, consumes them and returns true.
  // Otherwise, consumes nothing and returns false.
  bool MatchPrefixAndConsume(HpackPrefix prefix);

  // The Decode* functions return true and fill in their arguments if
  // decoding was successful, or false if an error was encountered.

  bool DecodeNextUint32(uint32* I);
  bool DecodeNextIdentityString(base::StringPiece* str);
  bool DecodeNextHuffmanString(const HpackHuffmanTable& table,
                               std::string* str);

  // Stores input bits into the most-significant, unfilled bits of |out|.
  // |peeked_count| is the number of filled bits in |out| which have been
  // previously peeked. PeekBits() will fill some number of remaining bits,
  // returning the new total number via |peeked_count|. Returns true if one
  // or more additional bits could be peeked, and false otherwise.
  bool PeekBits(size_t* peeked_count, uint32* out);

  // Consumes |count| bits of input. Generally paired with PeekBits().
  void ConsumeBits(size_t count);

  // If not currently on a byte boundary, consumes and discards
  // remaining bits in the current byte.
  void ConsumeByteRemainder();

  // Accessors for testing.

  void SetBitOffsetForTest(size_t bit_offset) {
    bit_offset_ = bit_offset;
  }

 private:
  const uint32 max_string_literal_size_;
  base::StringPiece buffer_;
  size_t bit_offset_;

  bool PeekNextOctet(uint8* next_octet);

  bool DecodeNextOctet(uint8* next_octet);

  DISALLOW_COPY_AND_ASSIGN(HpackInputStream);
};

}  // namespace net

#endif  // NET_SPDY_HPACK_INPUT_STREAM_H_
