// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_HPACK_HUFFMAN_DECODER_H_
#define NET_SPDY_HPACK_HPACK_HUFFMAN_DECODER_H_

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "net/base/net_export.h"
#include "net/spdy/hpack/hpack_input_stream.h"

namespace net {
namespace test {
class HpackHuffmanDecoderPeer;
}  // namespace test

// Declared as a class to simplify testing.
// No instances are actually allocated.
class NET_EXPORT_PRIVATE HpackHuffmanDecoder {
 public:
  typedef uint32_t HuffmanWord;
  typedef size_t HuffmanCodeLength;

  HpackHuffmanDecoder() = delete;

  // Decodes a string that has been encoded using the HPACK Huffman Code (see
  // https://httpwg.github.io/specs/rfc7541.html#huffman.code), reading the
  // encoded bitstream from |*in|, appending each decoded char to |*out|.
  // To avoid repeatedly growing the |*out| string, the caller should reserve
  // sufficient space in |*out| to hold decoded output.
  // DecodeString() halts when |in| runs out of input, in which case true is
  // returned. It also halts (returning false) if an invalid Huffman code
  // prefix is read.
  static bool DecodeString(HpackInputStream* in, std::string* out);

 private:
  friend class test::HpackHuffmanDecoderPeer;

  // The following private methods are declared here rather than simply
  // inlined into DecodeString so that they can be tested directly.

  // Returns the length (in bits) of the HPACK Huffman code that starts with
  // the high bits of |value|.
  static HuffmanCodeLength CodeLengthOfPrefix(HuffmanWord value);

  // Decodes the code in the high |code_length| bits of |bits| to the
  // corresponding canonical symbol.
  // Returns a value in the range [0, 256] (257 values). 256 is the EOS symbol,
  // which must not be explicitly encoded; the HPACK spec says that a decoder
  // must treat EOS as a decoding error.
  // Note that the canonical symbol is not the final value to be output because
  // the source symbols are not in descending probability order, so another
  // translation is required (see CanonicalToSource below).
  static HuffmanWord DecodeToCanonical(HuffmanCodeLength code_length,
                                       HuffmanWord bits);

  // Converts a canonical symbol to the source symbol (the char in the original
  // string that was encoded).
  static char CanonicalToSource(HuffmanWord canonical);
};

}  // namespace net

#endif  // NET_SPDY_HPACK_HPACK_HUFFMAN_DECODER_H_
