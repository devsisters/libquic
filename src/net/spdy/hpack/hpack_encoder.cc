// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack/hpack_encoder.h"

#include <algorithm>
#include <limits>

#include "base/logging.h"
#include "net/spdy/hpack/hpack_constants.h"
#include "net/spdy/hpack/hpack_header_table.h"
#include "net/spdy/hpack/hpack_huffman_table.h"
#include "net/spdy/hpack/hpack_output_stream.h"

namespace net {

using base::StringPiece;
using std::string;

HpackEncoder::HpackEncoder(const HpackHuffmanTable& table)
    : output_stream_(),
      huffman_table_(table),
      min_table_size_setting_received_(std::numeric_limits<size_t>::max()),
      allow_huffman_compression_(true),
      should_emit_table_size_(false) {}

HpackEncoder::~HpackEncoder() {}

bool HpackEncoder::EncodeHeaderSet(const SpdyHeaderBlock& header_set,
                                   string* output) {
  MaybeEmitTableSize();
  // Separate header set into pseudo-headers and regular headers.
  Representations pseudo_headers;
  Representations regular_headers;
  bool found_cookie = false;
  for (const auto& header : header_set) {
    if (!found_cookie && header.first == "cookie") {
      // Note that there can only be one "cookie" header, because header_set is
      // a map.
      found_cookie = true;
      CookieToCrumbs(header, &regular_headers);
    } else if (!header.first.empty() &&
               header.first[0] == kPseudoHeaderPrefix) {
      DecomposeRepresentation(header, &pseudo_headers);
    } else {
      DecomposeRepresentation(header, &regular_headers);
    }
  }

  // Encode pseudo-headers.
  bool found_authority = false;
  for (const auto& header : pseudo_headers) {
    const HpackEntry* entry =
        header_table_.GetByNameAndValue(header.first, header.second);
    if (entry != NULL) {
      EmitIndex(entry);
    } else {
      // :authority is always present and rarely changes, and has moderate
      // length, therefore it makes a lot of sense to index (insert in the
      // header table).
      if (!found_authority && header.first == ":authority") {
        // Note that there can only be one ":authority" header, because
        // |header_set| is a map.
        found_authority = true;
        EmitIndexedLiteral(header);
      } else {
        // Most common pseudo-header fields are represented in the static table,
        // while uncommon ones are small, so do not index them.
        EmitNonIndexedLiteral(header);
      }
    }
  }

  // Encode regular headers.
  for (const auto& header : regular_headers) {
    const HpackEntry* entry =
        header_table_.GetByNameAndValue(header.first, header.second);
    if (entry != NULL) {
      EmitIndex(entry);
    } else {
      EmitIndexedLiteral(header);
    }
  }

  output_stream_.TakeString(output);
  return true;
}

bool HpackEncoder::EncodeHeaderSetWithoutCompression(
    const SpdyHeaderBlock& header_set,
    string* output) {
  allow_huffman_compression_ = false;
  MaybeEmitTableSize();
  for (const auto& header : header_set) {
    // Note that cookies are not crumbled in this case.
    EmitNonIndexedLiteral(header);
  }
  allow_huffman_compression_ = true;
  output_stream_.TakeString(output);
  return true;
}

void HpackEncoder::ApplyHeaderTableSizeSetting(size_t size_setting) {
  if (size_setting == header_table_.settings_size_bound()) {
    return;
  }
  if (size_setting < header_table_.settings_size_bound()) {
    min_table_size_setting_received_ =
        std::min(size_setting, min_table_size_setting_received_);
  }
  header_table_.SetSettingsHeaderTableSize(size_setting);
  should_emit_table_size_ = true;
}

void HpackEncoder::EmitIndex(const HpackEntry* entry) {
  output_stream_.AppendPrefix(kIndexedOpcode);
  output_stream_.AppendUint32(header_table_.IndexOf(entry));
}

void HpackEncoder::EmitIndexedLiteral(const Representation& representation) {
  output_stream_.AppendPrefix(kLiteralIncrementalIndexOpcode);
  EmitLiteral(representation);
  header_table_.TryAddEntry(representation.first, representation.second);
}

void HpackEncoder::EmitNonIndexedLiteral(const Representation& representation) {
  output_stream_.AppendPrefix(kLiteralNoIndexOpcode);
  output_stream_.AppendUint32(0);
  EmitString(representation.first);
  EmitString(representation.second);
}

void HpackEncoder::EmitLiteral(const Representation& representation) {
  const HpackEntry* name_entry = header_table_.GetByName(representation.first);
  if (name_entry != NULL) {
    output_stream_.AppendUint32(header_table_.IndexOf(name_entry));
  } else {
    output_stream_.AppendUint32(0);
    EmitString(representation.first);
  }
  EmitString(representation.second);
}

void HpackEncoder::EmitString(StringPiece str) {
  size_t encoded_size =
      (!allow_huffman_compression_ ? str.size()
                                   : huffman_table_.EncodedSize(str));
  if (encoded_size < str.size()) {
    output_stream_.AppendPrefix(kStringLiteralHuffmanEncoded);
    output_stream_.AppendUint32(encoded_size);
    huffman_table_.EncodeString(str, &output_stream_);
  } else {
    output_stream_.AppendPrefix(kStringLiteralIdentityEncoded);
    output_stream_.AppendUint32(str.size());
    output_stream_.AppendBytes(str);
  }
}

void HpackEncoder::MaybeEmitTableSize() {
  if (!should_emit_table_size_) {
    return;
  }
  const size_t current_size = CurrentHeaderTableSizeSetting();
  if (min_table_size_setting_received_ < current_size) {
    output_stream_.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream_.AppendUint32(min_table_size_setting_received_);
  }
  output_stream_.AppendPrefix(kHeaderTableSizeUpdateOpcode);
  output_stream_.AppendUint32(current_size);
  min_table_size_setting_received_ = std::numeric_limits<size_t>::max();
  should_emit_table_size_ = false;
}

// static
void HpackEncoder::CookieToCrumbs(const Representation& cookie,
                                  Representations* out) {
  // See Section 8.1.2.5. "Compressing the Cookie Header Field" in the HTTP/2
  // specification at https://tools.ietf.org/html/draft-ietf-httpbis-http2-14.
  // Cookie values are split into individually-encoded HPACK representations.
  StringPiece cookie_value = cookie.second;
  // Consume leading and trailing whitespace if present.
  StringPiece::size_type first = cookie_value.find_first_not_of(" \t");
  StringPiece::size_type last = cookie_value.find_last_not_of(" \t");
  if (first == StringPiece::npos) {
    cookie_value.clear();
  } else {
    cookie_value = cookie_value.substr(first, (last - first) + 1);
  }
  for (size_t pos = 0;;) {
    size_t end = cookie_value.find(";", pos);

    if (end == StringPiece::npos) {
      out->push_back(std::make_pair(cookie.first, cookie_value.substr(pos)));
      break;
    }
    out->push_back(
        std::make_pair(cookie.first, cookie_value.substr(pos, end - pos)));

    // Consume next space if present.
    pos = end + 1;
    if (pos != cookie_value.size() && cookie_value[pos] == ' ') {
      pos++;
    }
  }
}

// static
void HpackEncoder::DecomposeRepresentation(const Representation& header_field,
                                           Representations* out) {
  size_t pos = 0;
  size_t end = 0;
  while (end != StringPiece::npos) {
    end = header_field.second.find('\0', pos);
    out->push_back(
        std::make_pair(header_field.first,
                       header_field.second.substr(
                           pos, end == StringPiece::npos ? end : end - pos)));
    pos = end + 1;
  }
}

}  // namespace net
