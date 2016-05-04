// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_INPUT_STREAM_H_
#define NET_SPDY_HPACK_INPUT_STREAM_H_

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <utility>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/spdy/hpack/hpack_constants.h"
#include "net/spdy/hpack/hpack_huffman_table.h"

// All section references below are to
// http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-08

namespace net {

namespace test {
class HpackInputStreamPeer;
}  // namespace test

typedef std::pair<size_t, uint32_t> InitialPeekResult;

// An HpackInputStream handles all the low-level details of decoding
// header fields.
class NET_EXPORT_PRIVATE HpackInputStream {
 public:
  friend class test::HpackInputStreamPeer;

  // |max_string_literal_size| is the largest that any one string
  // literal (header name or header value) can be.
  HpackInputStream(uint32_t max_string_literal_size, base::StringPiece buffer);
  ~HpackInputStream();

  // Returns whether or not there is more data to process.
  bool HasMoreData() const;

  // If the next bits of input match |prefix|, consumes them and returns true.
  // Otherwise, consumes nothing and returns false.
  bool MatchPrefixAndConsume(HpackPrefix prefix);

  // The Decode* functions return true and fill in their arguments if
  // decoding was successful, or false if an error was encountered.

  bool DecodeNextUint32(uint32_t* I);
  bool DecodeNextIdentityString(base::StringPiece* str);
  bool DecodeNextHuffmanString(std::string* str);

  // Stores input bits into the most-significant, unfilled bits of |out|.
  // |peeked_count| is the number of filled bits in |out| which have been
  // previously peeked. PeekBits() will fill some number of remaining bits,
  // returning the new total number via |peeked_count|. Returns true if one
  // or more additional bits were added to |out|, and false otherwise.
  bool PeekBits(size_t* peeked_count, uint32_t* out) const;

  // Similar to PeekBits, but intended to be used when starting to decode a
  // Huffman encoded string. Returns a pair containing the peeked_count and
  // out values as described for PeekBits, with the bits from the first N bytes
  // of buffer_, where N == min(4, buffer_.size()), starting with the high
  // order bits.
  // Should only be called when first peeking at bits from the input stream as
  // it does not take peeked_count as an input, so doesn't know how many bits
  // have already been returned by previous calls to InitializePeekBits and
  // PeekBits.
  InitialPeekResult InitializePeekBits();

  // Consumes |count| bits of input. Generally paired with PeekBits().
  void ConsumeBits(size_t count);

  // If not currently on a byte boundary, consumes and discards
  // remaining bits in the current byte.
  void ConsumeByteRemainder();

  // Return the total bytes that have been parsed SUCCESSFULLY.
  uint32_t ParsedBytes() const;

  // When incrementally decode the header, need to remember the current
  // position in the buffer after we successfully decode one opcode.
  void MarkCurrentPosition();

  // Returning true indicates this instance of HpackInputStream
  // doesn't have enough data to parse the current opcode, and we
  // are done with this instance. When more data arrive, a new
  // HpackInputStream should be created to restart the parsing.
  bool NeedMoreData() const;

 private:
  const uint32_t max_string_literal_size_;
  base::StringPiece buffer_;
  size_t bit_offset_;
  // Total number of bytes parsed successfully. Only get updated when an
  // opcode is parsed successfully.
  uint32_t parsed_bytes_;
  // Total number of bytes parsed currently. Get updated when an octet,
  // a number or a string has been parsed successfully. Can point to the
  // middle of an opcode.
  uint32_t parsed_bytes_current_;
  bool need_more_data_;

  bool PeekNextOctet(uint8_t* next_octet);

  bool DecodeNextOctet(uint8_t* next_octet);

  DISALLOW_COPY_AND_ASSIGN(HpackInputStream);
};

}  // namespace net

#endif  // NET_SPDY_HPACK_INPUT_STREAM_H_
