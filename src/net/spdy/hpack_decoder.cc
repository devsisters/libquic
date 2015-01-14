// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack_decoder.h"

#include "base/basictypes.h"
#include "base/logging.h"
#include "net/spdy/hpack_constants.h"
#include "net/spdy/hpack_output_stream.h"

namespace net {

using base::StringPiece;
using std::string;

namespace {

const char kCookieKey[] = "cookie";

}  // namespace

HpackDecoder::HpackDecoder(const HpackHuffmanTable& table)
    : max_string_literal_size_(kDefaultMaxStringLiteralSize),
      regular_header_seen_(false),
      huffman_table_(table) {}

HpackDecoder::~HpackDecoder() {}

bool HpackDecoder::HandleControlFrameHeadersData(SpdyStreamId id,
                                                 const char* headers_data,
                                                 size_t headers_data_length) {
  decoded_block_.clear();

  size_t new_size = headers_block_buffer_.size() + headers_data_length;
  if (new_size > kMaxDecodeBufferSize) {
    return false;
  }
  headers_block_buffer_.insert(headers_block_buffer_.end(),
                               headers_data,
                               headers_data + headers_data_length);
  return true;
}

bool HpackDecoder::HandleControlFrameHeadersComplete(SpdyStreamId id) {
  HpackInputStream input_stream(max_string_literal_size_,
                                headers_block_buffer_);
  regular_header_seen_ = false;
  while (input_stream.HasMoreData()) {
    if (!DecodeNextOpcode(&input_stream)) {
      headers_block_buffer_.clear();
      return false;
    }
  }
  headers_block_buffer_.clear();

  // Emit the Cookie header, if any crumbles were encountered.
  if (!cookie_value_.empty()) {
    decoded_block_[kCookieKey] = cookie_value_;
    cookie_value_.clear();
  }
  return true;
}

bool HpackDecoder::HandleHeaderRepresentation(StringPiece name,
                                              StringPiece value) {
  typedef std::pair<std::map<string, string>::iterator, bool> InsertResult;

  // Fail if pseudo-header follows regular header.
  if (name.size() > 0) {
    if (name[0] == kPseudoHeaderPrefix) {
      if (regular_header_seen_) return false;
    } else {
      regular_header_seen_ = true;
    }
  }

  if (name == kCookieKey) {
    if (cookie_value_.empty()) {
      cookie_value_.assign(value.data(), value.size());
    } else {
      cookie_value_ += "; ";
      cookie_value_.insert(cookie_value_.end(), value.begin(), value.end());
    }
  } else {
    InsertResult result = decoded_block_.insert(
        std::make_pair(name.as_string(), value.as_string()));
    if (!result.second) {
      result.first->second.push_back('\0');
      result.first->second.insert(result.first->second.end(),
                                  value.begin(),
                                  value.end());
    }
  }
  return true;
}

bool HpackDecoder::DecodeNextOpcode(HpackInputStream* input_stream) {
  // Implements 7.1: Indexed Header Field Representation.
  if (input_stream->MatchPrefixAndConsume(kIndexedOpcode)) {
    return DecodeNextIndexedHeader(input_stream);
  }
  // Implements 7.2.1: Literal Header Field with Incremental Indexing.
  if (input_stream->MatchPrefixAndConsume(kLiteralIncrementalIndexOpcode)) {
    return DecodeNextLiteralHeader(input_stream, true);
  }
  // Implements 7.2.2: Literal Header Field without Indexing.
  if (input_stream->MatchPrefixAndConsume(kLiteralNoIndexOpcode)) {
    return DecodeNextLiteralHeader(input_stream, false);
  }
  // Implements 7.2.3: Literal Header Field never Indexed.
  // TODO(jgraettinger): Preserve the never-indexed bit.
  if (input_stream->MatchPrefixAndConsume(kLiteralNeverIndexOpcode)) {
    return DecodeNextLiteralHeader(input_stream, false);
  }
  // Implements 7.3: Header Table Size Update.
  if (input_stream->MatchPrefixAndConsume(kHeaderTableSizeUpdateOpcode)) {
    return DecodeNextHeaderTableSizeUpdate(input_stream);
  }
  // Unrecognized opcode.
  return false;
}

bool HpackDecoder::DecodeNextHeaderTableSizeUpdate(
    HpackInputStream* input_stream) {
  uint32 size = 0;
  if (!input_stream->DecodeNextUint32(&size)) {
    return false;
  }
  if (size > header_table_.settings_size_bound()) {
    return false;
  }
  header_table_.SetMaxSize(size);
  return true;
}

bool HpackDecoder::DecodeNextIndexedHeader(HpackInputStream* input_stream) {
  uint32 index = 0;
  if (!input_stream->DecodeNextUint32(&index))
    return false;

  const HpackEntry* entry = header_table_.GetByIndex(index);
  if (entry == NULL)
    return false;

  return HandleHeaderRepresentation(entry->name(), entry->value());
}

bool HpackDecoder::DecodeNextLiteralHeader(HpackInputStream* input_stream,
                                           bool should_index) {
  StringPiece name;
  if (!DecodeNextName(input_stream, &name))
    return false;

  StringPiece value;
  if (!DecodeNextStringLiteral(input_stream, false, &value))
    return false;

  if (!HandleHeaderRepresentation(name, value)) return false;

  if (!should_index)
    return true;

  ignore_result(header_table_.TryAddEntry(name, value));
  return true;
}

bool HpackDecoder::DecodeNextName(
    HpackInputStream* input_stream, StringPiece* next_name) {
  uint32 index_or_zero = 0;
  if (!input_stream->DecodeNextUint32(&index_or_zero))
    return false;

  if (index_or_zero == 0)
    return DecodeNextStringLiteral(input_stream, true, next_name);

  const HpackEntry* entry = header_table_.GetByIndex(index_or_zero);
  if (entry == NULL) {
    return false;
  } else if (entry->IsStatic()) {
    *next_name = entry->name();
  } else {
    // |entry| could be evicted as part of this insertion. Preemptively copy.
    key_buffer_.assign(entry->name());
    *next_name = key_buffer_;
  }
  return true;
}

bool HpackDecoder::DecodeNextStringLiteral(HpackInputStream* input_stream,
                                           bool is_key,
                                           StringPiece* output) {
  if (input_stream->MatchPrefixAndConsume(kStringLiteralHuffmanEncoded)) {
    string* buffer = is_key ? &key_buffer_ : &value_buffer_;
    bool result = input_stream->DecodeNextHuffmanString(huffman_table_, buffer);
    *output = StringPiece(*buffer);
    return result;
  } else if (input_stream->MatchPrefixAndConsume(
      kStringLiteralIdentityEncoded)) {
    return input_stream->DecodeNextIdentityString(output);
  } else {
    return false;
  }
}

}  // namespace net
