// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_CONSTANTS_H_
#define NET_SPDY_HPACK_CONSTANTS_H_

#include <vector>

#include "base/basictypes.h"
#include "net/base/net_export.h"

// All section references below are to
// http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-08

namespace net {

// An HpackPrefix signifies |bits| stored in the top |bit_size| bits
// of an octet.
struct HpackPrefix {
  uint8 bits;
  size_t bit_size;
};

// Represents a symbol and its Huffman code (stored in most-significant bits).
struct HpackHuffmanSymbol {
  uint32 code;
  uint8 length;
  uint16 id;
};

// An entry in the static table. Must be a POD in order to avoid static
// initializers, i.e. no user-defined constructors or destructors.
struct HpackStaticEntry {
  const char* const name;
  const size_t name_len;
  const char* const value;
  const size_t value_len;
};

class HpackHuffmanTable;
class HpackStaticTable;

const uint32 kDefaultHeaderTableSizeSetting = 4096;

// Largest string literal an HpackDecoder/HpackEncoder will attempt to process
// before returning an error.
const uint32 kDefaultMaxStringLiteralSize = 16 * 1024;

// Maximum amount of encoded header buffer HpackDecoder will retain before
// returning an error.
// TODO(jgraettinger): Remove with SpdyHeadersHandlerInterface switch.
const uint32 kMaxDecodeBufferSize = 32 * 1024;

// 6.2: Flag for a string literal that is stored unmodified (i.e.,
// without Huffman encoding).
const HpackPrefix kStringLiteralIdentityEncoded = { 0x0, 1 };

// 6.2: Flag for a Huffman-coded string literal.
const HpackPrefix kStringLiteralHuffmanEncoded = { 0x1, 1 };

// 7.1: Opcode for an indexed header field.
const HpackPrefix kIndexedOpcode = { 0x1, 1 };

// 7.2.1: Opcode for a literal header field with incremental indexing.
const HpackPrefix kLiteralIncrementalIndexOpcode = { 0x1, 2 };

// 7.2.2: Opcode for a literal header field without indexing.
const HpackPrefix kLiteralNoIndexOpcode = { 0x0, 4 };

// 7.2.3: Opcode for a literal header field which is never indexed.
const HpackPrefix kLiteralNeverIndexOpcode = { 0x1, 4 };

// 7.3: Opcode for maximum header table size update. Begins a varint-encoded
// table size with a 5-bit prefix.
const HpackPrefix kHeaderTableSizeUpdateOpcode = { 0x1, 3 };

// Returns symbol code table from "Appendix C. Huffman Code".
NET_EXPORT_PRIVATE std::vector<HpackHuffmanSymbol> HpackHuffmanCode();

// Returns static table from "Appendix B. Static Table Definition".
NET_EXPORT_PRIVATE std::vector<HpackStaticEntry> HpackStaticTableVector();

// Returns a HpackHuffmanTable instance initialized with |kHpackHuffmanCode|.
// The instance is read-only, has static lifetime, and is safe to share amoung
// threads. This function is thread-safe.
NET_EXPORT_PRIVATE const HpackHuffmanTable& ObtainHpackHuffmanTable();

// Returns a HpackStaticTable instance initialized with |kHpackStaticTable|.
// The instance is read-only, has static lifetime, and is safe to share amoung
// threads. This function is thread-safe.
NET_EXPORT_PRIVATE const HpackStaticTable& ObtainHpackStaticTable();

// Pseudo-headers start with a colon.  (HTTP2 8.1.2.1., HPACK 3.1.)
const char kPseudoHeaderPrefix = ':';

}  // namespace net

#endif  // NET_SPDY_HPACK_CONSTANTS_H_
