// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack_encoder.h"

#include <algorithm>

#include "base/logging.h"
#include "net/spdy/hpack_header_table.h"
#include "net/spdy/hpack_huffman_table.h"
#include "net/spdy/hpack_output_stream.h"

namespace net {

using base::StringPiece;
using std::string;

HpackEncoder::HpackEncoder(const HpackHuffmanTable& table)
    : output_stream_(),
      allow_huffman_compression_(true),
      huffman_table_(table),
      char_counts_(NULL),
      total_char_counts_(NULL) {}

HpackEncoder::~HpackEncoder() {}

bool HpackEncoder::EncodeHeaderSet(const std::map<string, string>& header_set,
                                   string* output) {
  // Separate header set into pseudo-headers and regular headers.
  Representations pseudo_headers;
  Representations regular_headers;
  for (std::map<string, string>::const_iterator it = header_set.begin();
       it != header_set.end(); ++it) {
    if (it->first == "cookie") {
      // Note that there can only be one "cookie" header, because header_set is
      // a map.
      CookieToCrumbs(*it, &regular_headers);
    } else if (it->first[0] == kPseudoHeaderPrefix) {
      DecomposeRepresentation(*it, &pseudo_headers);
    } else {
      DecomposeRepresentation(*it, &regular_headers);
    }
  }

  // Encode pseudo-headers.
  for (Representations::const_iterator it = pseudo_headers.begin();
       it != pseudo_headers.end(); ++it) {
    const HpackEntry* entry =
        header_table_.GetByNameAndValue(it->first, it->second);
    if (entry != NULL) {
      EmitIndex(entry);
    } else {
      if (it->first == ":authority") {
        // :authority is always present and rarely changes, and has moderate
        // length, therefore it makes a lot of sense to index (insert in the
        // header table).
        EmitIndexedLiteral(*it);
      } else {
        // Most common pseudo-header fields are represented in the static table,
        // while uncommon ones are small, so do not index them.
        EmitNonIndexedLiteral(*it);
      }
    }
  }

  // Encode regular headers.
  for (Representations::const_iterator it = regular_headers.begin();
       it != regular_headers.end(); ++it) {
    const HpackEntry* entry =
        header_table_.GetByNameAndValue(it->first, it->second);
    if (entry != NULL) {
      EmitIndex(entry);
    } else {
      EmitIndexedLiteral(*it);
    }
  }

  output_stream_.TakeString(output);
  return true;
}

bool HpackEncoder::EncodeHeaderSetWithoutCompression(
    const std::map<string, string>& header_set,
    string* output) {

  allow_huffman_compression_ = false;
  for (std::map<string, string>::const_iterator it = header_set.begin();
       it != header_set.end(); ++it) {
    // Note that cookies are not crumbled in this case.
    EmitNonIndexedLiteral(*it);
  }
  allow_huffman_compression_ = true;
  output_stream_.TakeString(output);
  return true;
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

void HpackEncoder::EmitNonIndexedLiteral(
    const Representation& representation) {
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
  size_t encoded_size = (!allow_huffman_compression_ ? str.size()
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
  UpdateCharacterCounts(str);
}

void HpackEncoder::SetCharCountsStorage(std::vector<size_t>* char_counts,
                                        size_t* total_char_counts) {
  CHECK_LE(256u, char_counts->size());
  char_counts_ = char_counts;
  total_char_counts_ = total_char_counts;
}

void HpackEncoder::UpdateCharacterCounts(base::StringPiece str) {
  if (char_counts_ == NULL || total_char_counts_ == NULL) {
    return;
  }
  for (StringPiece::const_iterator it = str.begin(); it != str.end(); ++it) {
    ++(*char_counts_)[static_cast<uint8>(*it)];
  }
  (*total_char_counts_) += str.size();
}

// static
void HpackEncoder::CookieToCrumbs(const Representation& cookie,
                                  Representations* out) {
  size_t prior_size = out->size();

  // See Section 8.1.2.5. "Compressing the Cookie Header Field" in the HTTP/2
  // specification at https://tools.ietf.org/html/draft-ietf-httpbis-http2-14.
  // Cookie values are split into individually-encoded HPACK representations.
  for (size_t pos = 0;;) {
    size_t end = cookie.second.find(";", pos);

    if (end == StringPiece::npos) {
      out->push_back(std::make_pair(cookie.first, cookie.second.substr(pos)));
      break;
    }
    out->push_back(
        std::make_pair(cookie.first, cookie.second.substr(pos, end - pos)));

    // Consume next space if present.
    pos = end + 1;
    if (pos != cookie.second.size() && cookie.second[pos] == ' ') {
      pos++;
    }
  }
  // Sort crumbs and remove duplicates.
  std::sort(out->begin() + prior_size, out->end());
  out->erase(std::unique(out->begin() + prior_size, out->end()),
             out->end());
}

// static
void HpackEncoder::DecomposeRepresentation(const Representation& header_field,
                                           Representations* out) {
  size_t pos = 0;
  size_t end = 0;
  while (end != StringPiece::npos) {
    end = header_field.second.find('\0', pos);
    out->push_back(std::make_pair(header_field.first,
                                  header_field.second.substr(pos, end - pos)));
    pos = end + 1;
  }
}

}  // namespace net
