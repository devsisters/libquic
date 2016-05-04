// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack/hpack_huffman_table.h"

#include <algorithm>
#include <cmath>
#include <memory>

#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "net/spdy/hpack/hpack_input_stream.h"
#include "net/spdy/hpack/hpack_output_stream.h"

namespace net {

using base::StringPiece;
using std::string;

namespace {

// How many bits to index in the root decode table.
const uint8_t kDecodeTableRootBits = 9;
// Maximum number of bits to index in successive decode tables.
const uint8_t kDecodeTableBranchBits = 6;

bool SymbolLengthAndIdCompare(const HpackHuffmanSymbol& a,
                              const HpackHuffmanSymbol& b) {
  if (a.length == b.length) {
    return a.id < b.id;
  }
  return a.length < b.length;
}
bool SymbolIdCompare(const HpackHuffmanSymbol& a, const HpackHuffmanSymbol& b) {
  return a.id < b.id;
}

}  // namespace

HpackHuffmanTable::DecodeEntry::DecodeEntry()
    : next_table_index(0), length(0), symbol_id(0) {}
HpackHuffmanTable::DecodeEntry::DecodeEntry(uint8_t next_table_index,
                                            uint8_t length,
                                            uint16_t symbol_id)
    : next_table_index(next_table_index),
      length(length),
      symbol_id(symbol_id) {}
size_t HpackHuffmanTable::DecodeTable::size() const {
  return size_t(1) << indexed_length;
}

HpackHuffmanTable::HpackHuffmanTable() {}

HpackHuffmanTable::~HpackHuffmanTable() {}

bool HpackHuffmanTable::Initialize(const HpackHuffmanSymbol* input_symbols,
                                   size_t symbol_count) {
  CHECK(!IsInitialized());
  DCHECK(base::IsValueInRangeForNumericType<uint16_t>(symbol_count));

  std::vector<Symbol> symbols(symbol_count);
  // Validate symbol id sequence, and copy into |symbols|.
  for (uint16_t i = 0; i < symbol_count; i++) {
    if (i != input_symbols[i].id) {
      failed_symbol_id_ = i;
      return false;
    }
    symbols[i] = input_symbols[i];
  }
  // Order on length and ID ascending, to verify symbol codes are canonical.
  std::sort(symbols.begin(), symbols.end(), SymbolLengthAndIdCompare);
  if (symbols[0].code != 0) {
    failed_symbol_id_ = 0;
    return false;
  }
  for (size_t i = 1; i != symbols.size(); i++) {
    unsigned code_shift = 32 - symbols[i - 1].length;
    uint32_t code = symbols[i - 1].code + (1 << code_shift);

    if (code != symbols[i].code) {
      failed_symbol_id_ = symbols[i].id;
      return false;
    }
    if (code < symbols[i - 1].code) {
      // An integer overflow occurred. This implies the input
      // lengths do not represent a valid Huffman code.
      failed_symbol_id_ = symbols[i].id;
      return false;
    }
  }
  if (symbols.back().length < 8) {
    // At least one code (such as an EOS symbol) must be 8 bits or longer.
    // Without this, some inputs will not be encodable in a whole number
    // of bytes.
    return false;
  }
  pad_bits_ = static_cast<uint8_t>(symbols.back().code >> 24);

  BuildDecodeTables(symbols);
  // Order on symbol ID ascending.
  std::sort(symbols.begin(), symbols.end(), SymbolIdCompare);
  BuildEncodeTable(symbols);
  return true;
}

void HpackHuffmanTable::BuildEncodeTable(const std::vector<Symbol>& symbols) {
  for (size_t i = 0; i != symbols.size(); i++) {
    const Symbol& symbol = symbols[i];
    CHECK_EQ(i, symbol.id);
    code_by_id_.push_back(symbol.code);
    length_by_id_.push_back(symbol.length);
  }
}

void HpackHuffmanTable::BuildDecodeTables(const std::vector<Symbol>& symbols) {
  AddDecodeTable(0, kDecodeTableRootBits);
  // We wish to maximize the flatness of the DecodeTable hierarchy (subject to
  // the |kDecodeTableBranchBits| constraint), and to minimize the size of
  // child tables. To achieve this, we iterate in order of descending code
  // length. This ensures that child tables are visited with their longest
  // entry first, and that the child can therefore be minimally sized to hold
  // that entry without fear of introducing unneccesary branches later.
  for (std::vector<Symbol>::const_reverse_iterator it = symbols.rbegin();
       it != symbols.rend(); ++it) {
    uint8_t table_index = 0;
    while (true) {
      const DecodeTable table = decode_tables_[table_index];

      // Mask and shift the portion of the code being indexed into low bits.
      uint32_t index = (it->code << table.prefix_length);
      index = index >> (32 - table.indexed_length);

      CHECK_LT(index, table.size());
      DecodeEntry entry = Entry(table, index);

      uint8_t total_indexed = table.prefix_length + table.indexed_length;
      if (total_indexed >= it->length) {
        // We're writing a terminal entry.
        entry.length = it->length;
        entry.symbol_id = it->id;
        entry.next_table_index = table_index;
        SetEntry(table, index, entry);
        break;
      }

      if (entry.length == 0) {
        // First visit to this placeholder. We need to create a new table.
        CHECK_EQ(entry.next_table_index, 0);
        entry.length = it->length;
        entry.next_table_index =
            AddDecodeTable(total_indexed,  // Becomes the new table prefix.
                           std::min<uint8_t>(kDecodeTableBranchBits,
                                             entry.length - total_indexed));
        SetEntry(table, index, entry);
      }
      CHECK_NE(entry.next_table_index, table_index);
      table_index = entry.next_table_index;
    }
  }
  // Fill shorter table entries into the additional entry spots they map to.
  for (size_t i = 0; i != decode_tables_.size(); i++) {
    const DecodeTable& table = decode_tables_[i];
    uint8_t total_indexed = table.prefix_length + table.indexed_length;

    size_t j = 0;
    while (j != table.size()) {
      const DecodeEntry& entry = Entry(table, j);
      if (entry.length != 0 && entry.length < total_indexed) {
        // The difference between entry & table bit counts tells us how
        // many additional entries map to this one.
        size_t fill_count = static_cast<size_t>(1)
                            << (total_indexed - entry.length);
        CHECK_LE(j + fill_count, table.size());

        for (size_t k = 1; k != fill_count; k++) {
          CHECK_EQ(Entry(table, j + k).length, 0);
          SetEntry(table, j + k, entry);
        }
        j += fill_count;
      } else {
        j++;
      }
    }
  }
}

uint8_t HpackHuffmanTable::AddDecodeTable(uint8_t prefix, uint8_t indexed) {
  CHECK_LT(decode_tables_.size(), 255u);
  {
    DecodeTable table;
    table.prefix_length = prefix;
    table.indexed_length = indexed;
    table.entries_offset = decode_entries_.size();
    decode_tables_.push_back(table);
  }
  decode_entries_.resize(decode_entries_.size() + (size_t(1) << indexed));
  return static_cast<uint8_t>(decode_tables_.size() - 1);
}

const HpackHuffmanTable::DecodeEntry& HpackHuffmanTable::Entry(
    const DecodeTable& table,
    uint32_t index) const {
  DCHECK_LT(index, table.size());
  DCHECK_LT(table.entries_offset + index, decode_entries_.size());
  return decode_entries_[table.entries_offset + index];
}

void HpackHuffmanTable::SetEntry(const DecodeTable& table,
                                 uint32_t index,
                                 const DecodeEntry& entry) {
  CHECK_LT(index, table.size());
  CHECK_LT(table.entries_offset + index, decode_entries_.size());
  decode_entries_[table.entries_offset + index] = entry;
}

bool HpackHuffmanTable::IsInitialized() const {
  return !code_by_id_.empty();
}

void HpackHuffmanTable::EncodeString(StringPiece in,
                                     HpackOutputStream* out) const {
  size_t bit_remnant = 0;
  for (size_t i = 0; i != in.size(); i++) {
    uint16_t symbol_id = static_cast<uint8_t>(in[i]);
    CHECK_GT(code_by_id_.size(), symbol_id);

    // Load, and shift code to low bits.
    unsigned length = length_by_id_[symbol_id];
    uint32_t code = code_by_id_[symbol_id] >> (32 - length);

    bit_remnant = (bit_remnant + length) % 8;

    if (length > 24) {
      out->AppendBits(static_cast<uint8_t>(code >> 24), length - 24);
      length = 24;
    }
    if (length > 16) {
      out->AppendBits(static_cast<uint8_t>(code >> 16), length - 16);
      length = 16;
    }
    if (length > 8) {
      out->AppendBits(static_cast<uint8_t>(code >> 8), length - 8);
      length = 8;
    }
    out->AppendBits(static_cast<uint8_t>(code), length);
  }
  if (bit_remnant != 0) {
    // Pad current byte as required.
    out->AppendBits(pad_bits_ >> bit_remnant, 8 - bit_remnant);
  }
}

size_t HpackHuffmanTable::EncodedSize(StringPiece in) const {
  size_t bit_count = 0;
  for (size_t i = 0; i != in.size(); i++) {
    uint16_t symbol_id = static_cast<uint8_t>(in[i]);
    CHECK_GT(code_by_id_.size(), symbol_id);

    bit_count += length_by_id_[symbol_id];
  }
  if (bit_count % 8 != 0) {
    bit_count += 8 - bit_count % 8;
  }
  return bit_count / 8;
}

bool HpackHuffmanTable::GenericDecodeString(HpackInputStream* in,
                                            size_t out_capacity,
                                            string* out) const {
  // Number of decode iterations required for a 32-bit code.
  const int kDecodeIterations = static_cast<int>(
      std::ceil((32.f - kDecodeTableRootBits) / kDecodeTableBranchBits));

  out->clear();

  // Current input, stored in the high |bits_available| bits of |bits|.
  uint32_t bits = 0;
  size_t bits_available = 0;
  bool peeked_success = in->PeekBits(&bits_available, &bits);

  while (true) {
    const DecodeTable* table = &decode_tables_[0];
    uint32_t index = bits >> (32 - kDecodeTableRootBits);

    for (int i = 0; i != kDecodeIterations; i++) {
      DCHECK_LT(index, table->size());
      DCHECK_LT(Entry(*table, index).next_table_index, decode_tables_.size());

      table = &decode_tables_[Entry(*table, index).next_table_index];
      // Mask and shift the portion of the code being indexed into low bits.
      index = (bits << table->prefix_length) >> (32 - table->indexed_length);
    }
    const DecodeEntry& entry = Entry(*table, index);

    if (entry.length > bits_available) {
      if (!peeked_success) {
        // Unable to read enough input for a match. If only a portion of
        // the last byte remains, this is a successful EOF condition.
        in->ConsumeByteRemainder();
        return !in->HasMoreData();
      }
    } else if (entry.length == 0) {
      // The input is an invalid prefix, larger than any prefix in the table.
      return false;
    } else {
      if (out->size() == out_capacity) {
        // This code would cause us to overflow |out_capacity|.
        return false;
      }
      if (entry.symbol_id < 256) {
        // Assume symbols >= 256 are used for padding.
        out->push_back(static_cast<char>(entry.symbol_id));
      }

      in->ConsumeBits(entry.length);
      bits = bits << entry.length;
      bits_available -= entry.length;
    }
    peeked_success = in->PeekBits(&bits_available, &bits);
  }
  NOTREACHED();
  return false;
}

}  // namespace net
