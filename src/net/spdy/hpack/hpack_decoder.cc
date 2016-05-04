// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack/hpack_decoder.h"

#include <utility>

#include "base/logging.h"
#include "net/spdy/hpack/hpack_constants.h"
#include "net/spdy/hpack/hpack_output_stream.h"

namespace net {

using base::StringPiece;
using std::string;

namespace {

const char kCookieKey[] = "cookie";

}  // namespace

HpackDecoder::HpackDecoder()
    : max_string_literal_size_(kDefaultMaxStringLiteralSize),
      handler_(nullptr),
      total_header_bytes_(0),
      regular_header_seen_(false),
      header_block_started_(false),
      total_parsed_bytes_(0) {}

HpackDecoder::~HpackDecoder() {}

bool HpackDecoder::HandleControlFrameHeadersData(const char* headers_data,
                                                 size_t headers_data_length) {
  if (!header_block_started_) {
    header_block_started_ = true;
    decoded_block_.clear();
    if (handler_ != nullptr) {
      handler_->OnHeaderBlockStart();
    }
  }
  size_t new_size = headers_block_buffer_.size() + headers_data_length;
  if (new_size > kMaxDecodeBufferSize) {
    return false;
  }
  headers_block_buffer_.insert(headers_block_buffer_.end(), headers_data,
                               headers_data + headers_data_length);

  // Parse as many data in buffer as possible. And remove the parsed data
  // from buffer.
  HpackInputStream input_stream(max_string_literal_size_,
                                headers_block_buffer_);
  while (input_stream.HasMoreData()) {
    if (!DecodeNextOpcodeWrapper(&input_stream)) {
      if (input_stream.NeedMoreData()) {
        break;
      }
      return false;
    }
  }
  uint32_t parsed_bytes = input_stream.ParsedBytes();
  DCHECK_GE(headers_block_buffer_.size(), parsed_bytes);
  headers_block_buffer_.erase(0, parsed_bytes);
  total_parsed_bytes_ += parsed_bytes;
  return true;
}

bool HpackDecoder::HandleControlFrameHeadersComplete(size_t* compressed_len) {
  regular_header_seen_ = false;

  if (compressed_len != nullptr) {
    *compressed_len = total_parsed_bytes_;
  }

  // Data in headers_block_buffer_ should have been parsed by
  // HandleControlFrameHeadersData and removed.
  if (headers_block_buffer_.size() > 0) {
    return false;
  }

  if (handler_ != nullptr) {
    handler_->OnHeaderBlockEnd(total_header_bytes_);
  }
  headers_block_buffer_.clear();
  total_parsed_bytes_ = 0;
  header_block_started_ = false;
  handler_ = nullptr;
  return true;
}

bool HpackDecoder::HandleHeaderRepresentation(StringPiece name,
                                              StringPiece value) {
  total_header_bytes_ += name.size() + value.size();

  // Fail if pseudo-header follows regular header.
  if (name.size() > 0) {
    if (name[0] == kPseudoHeaderPrefix) {
      if (regular_header_seen_) {
        return false;
      }
    } else {
      regular_header_seen_ = true;
    }
  }

  if (handler_ == nullptr) {
    auto it = decoded_block_.find(name);
    if (it == decoded_block_.end()) {
      // This is a new key.
      decoded_block_[name] = value;
    } else {
      // The key already exists, append |value| with appropriate delimiter.
      string new_value = it->second.as_string();
      new_value.append((name == kCookieKey) ? "; " : string(1, '\0'));
      value.AppendToString(&new_value);
      decoded_block_.ReplaceOrAppendHeader(name, new_value);
    }
  } else {
    DCHECK(decoded_block_.empty());
    handler_->OnHeader(name, value);
  }
  return true;
}

bool HpackDecoder::DecodeNextOpcodeWrapper(HpackInputStream* input_stream) {
  if (DecodeNextOpcode(input_stream)) {
    // Decoding next opcode succeeds. Mark total bytes parsed successfully.
    input_stream->MarkCurrentPosition();
    return true;
  }
  return false;
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
  uint32_t size = 0;
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
  uint32_t index = 0;
  if (!input_stream->DecodeNextUint32(&index)) {
    return false;
  }

  const HpackEntry* entry = header_table_.GetByIndex(index);
  if (entry == NULL) {
    return false;
  }

  return HandleHeaderRepresentation(entry->name(), entry->value());
}

bool HpackDecoder::DecodeNextLiteralHeader(HpackInputStream* input_stream,
                                           bool should_index) {
  StringPiece name;
  if (!DecodeNextName(input_stream, &name)) {
    return false;
  }

  StringPiece value;
  if (!DecodeNextStringLiteral(input_stream, false, &value)) {
    return false;
  }

  if (!HandleHeaderRepresentation(name, value)) {
    return false;
  }

  if (!should_index) {
    return true;
  }

  ignore_result(header_table_.TryAddEntry(name, value));
  return true;
}

bool HpackDecoder::DecodeNextName(HpackInputStream* input_stream,
                                  StringPiece* next_name) {
  uint32_t index_or_zero = 0;
  if (!input_stream->DecodeNextUint32(&index_or_zero)) {
    return false;
  }

  if (index_or_zero == 0) {
    return DecodeNextStringLiteral(input_stream, true, next_name);
  }

  const HpackEntry* entry = header_table_.GetByIndex(index_or_zero);
  if (entry == NULL) {
    return false;
  }
  if (entry->IsStatic()) {
    *next_name = entry->name();
  } else {
    // |entry| could be evicted as part of this insertion. Preemptively copy.
    key_buffer_.assign(entry->name().data(), entry->name().size());
    *next_name = key_buffer_;
  }
  return true;
}

bool HpackDecoder::DecodeNextStringLiteral(HpackInputStream* input_stream,
                                           bool is_key,
                                           StringPiece* output) {
  if (input_stream->MatchPrefixAndConsume(kStringLiteralHuffmanEncoded)) {
    string* buffer = is_key ? &key_buffer_ : &value_buffer_;
    bool result = input_stream->DecodeNextHuffmanString(buffer);
    *output = StringPiece(*buffer);
    return result;
  }
  if (input_stream->MatchPrefixAndConsume(kStringLiteralIdentityEncoded)) {
    return input_stream->DecodeNextIdentityString(output);
  }
  return false;
}

}  // namespace net
