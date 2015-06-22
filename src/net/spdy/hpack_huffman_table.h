// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_HUFFMAN_TABLE_H_
#define NET_SPDY_HPACK_HUFFMAN_TABLE_H_

#include <cstddef>
#include <string>
#include <vector>

#include "base/basictypes.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/spdy/hpack_constants.h"

namespace net {

namespace test {
class HpackHuffmanTablePeer;
}  // namespace test

class HpackInputStream;
class HpackOutputStream;

// HpackHuffmanTable encodes and decodes string literals using a constructed
// canonical Huffman code. Once initialized, an instance is read only and
// may be accessed only through its const interface.
class NET_EXPORT_PRIVATE HpackHuffmanTable {
 public:
  friend class test::HpackHuffmanTablePeer;

  typedef HpackHuffmanSymbol Symbol;

  // DecodeTables are multilevel indexes on code prefixes. Each table indexes
  // a portion of the prefix mapped to DecodeEntry, which in turn either
  // captures a terminal symbol, or points to the next DecodeTable to consult
  // with successive portions of the prefix.
  struct NET_EXPORT_PRIVATE DecodeEntry {
    DecodeEntry();
    DecodeEntry(uint8 next_table_index, uint8 length, uint16 symbol_id);

    // The next table to consult. If this is a terminal,
    // |next_table_index| will be self-referential.
    uint8 next_table_index;
    // Bit-length of terminal code, if this is a terminal. Length of the
    // longest code having this prefix, if non-terminal.
    uint8 length;
    // Set only for terminal entries.
    uint16 symbol_id;
  };
  struct NET_EXPORT_PRIVATE DecodeTable {
    // Number of bits indexed by the chain leading to this table.
    uint8 prefix_length;
    // Number of additional prefix bits this table indexes.
    uint8 indexed_length;
    // Entries are represented as a length |size()| slice into
    // |decode_entries_| beginning at |entries_offset|.
    size_t entries_offset;
    // Returns |1 << indexed_length|.
    size_t size() const;
  };

  HpackHuffmanTable();
  ~HpackHuffmanTable();

  // Prepares HpackHuffmanTable to encode & decode the canonical Huffman
  // code as determined by the given symbols. Must be called exactly once.
  // Returns false if the input symbols define an invalid coding, and true
  // otherwise. Symbols must be presented in ascending ID order with no gaps,
  // and |symbol_count| must fit in a uint16.
  bool Initialize(const Symbol* input_symbols, size_t symbol_count);

  // Returns whether Initialize() has been successfully called.
  bool IsInitialized() const;

  // Encodes the input string to the output stream using the table's Huffman
  // context.
  void EncodeString(base::StringPiece in, HpackOutputStream* out) const;

  // Returns the encoded size of the input string.
  size_t EncodedSize(base::StringPiece in) const;

  // Decodes symbols from |in| into |out|. It is the caller's responsibility
  // to ensure |out| has a reserved a sufficient buffer to hold decoded output.
  // DecodeString() halts when |in| runs out of input, in which case true is
  // returned. It also halts (returning false) if an invalid Huffman code
  // prefix is read, or if |out_capacity| would otherwise be overflowed.
  bool DecodeString(HpackInputStream* in,
                    size_t out_capacity,
                    std::string* out) const;

 private:
  // Expects symbols ordered on length & ID ascending.
  void BuildDecodeTables(const std::vector<Symbol>& symbols);

  // Expects symbols ordered on ID ascending.
  void BuildEncodeTable(const std::vector<Symbol>& symbols);

  // Adds a new DecodeTable with the argument prefix & indexed length.
  // Returns the new table index.
  uint8 AddDecodeTable(uint8 prefix, uint8 indexed);

  const DecodeEntry& Entry(const DecodeTable& table, uint32 index) const;

  void SetEntry(const DecodeTable& table, uint32 index,
                const DecodeEntry& entry);

  std::vector<DecodeTable> decode_tables_;
  std::vector<DecodeEntry> decode_entries_;

  // Symbol code and code length, in ascending symbol ID order.
  // Codes are stored in the most-significant bits of the word.
  std::vector<uint32> code_by_id_;
  std::vector<uint8> length_by_id_;

  // The first 8 bits of the longest code. Applied when generating padding bits.
  uint8 pad_bits_;

  // If initialization fails, preserve the symbol ID which failed validation
  // for examination in tests.
  uint16 failed_symbol_id_;
};

}  // namespace net

#endif  // NET_SPDY_HPACK_HUFFMAN_TABLE_H_
