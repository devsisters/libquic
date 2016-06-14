// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_headers_block_parser.h"

#include "base/sys_byteorder.h"
#include "net/spdy/spdy_bug_tracker.h"

namespace net {
namespace {

// 0 is invalid according to both the SPDY 3.1 and HTTP/2 specifications.
const SpdyStreamId kInvalidStreamId = 0;

}  // anonymous namespace

namespace {
const size_t kLengthFieldSize = sizeof(uint32_t);
}  // anonymous namespace

const size_t SpdyHeadersBlockParser::kMaximumFieldLength = 16 * 1024;

SpdyHeadersBlockParser::SpdyHeadersBlockParser(
    SpdyMajorVersion spdy_version,
    SpdyHeadersHandlerInterface* handler)
    : state_(READING_HEADER_BLOCK_LEN),
      max_headers_in_block_(MaxNumberOfHeaders()),
      total_bytes_received_(0),
      remaining_key_value_pairs_for_frame_(0),
      handler_(handler),
      stream_id_(kInvalidStreamId),
      error_(NO_PARSER_ERROR),
      spdy_version_(spdy_version) {
  // The handler that we set must not be NULL.
  DCHECK(handler_ != NULL);
}

SpdyHeadersBlockParser::~SpdyHeadersBlockParser() {}

bool SpdyHeadersBlockParser::HandleControlFrameHeadersData(
    SpdyStreamId stream_id,
    const char* headers_data,
    size_t headers_data_length) {
  if (error_ == NEED_MORE_DATA) {
    error_ = NO_PARSER_ERROR;
  }
  if (error_ != NO_PARSER_ERROR) {
    SPDY_BUG << "Unexpected error: " << error_;
    return false;
  }

  // If this is the first call with the current header block,
  // save its stream id.
  if (state_ == READING_HEADER_BLOCK_LEN && stream_id_ == kInvalidStreamId) {
    stream_id_ = stream_id;
  }
  if (stream_id != stream_id_) {
    SPDY_BUG << "Unexpected stream id: " << stream_id << " (expected "
             << stream_id_ << ")";
    error_ = UNEXPECTED_STREAM_ID;
    return false;
  }
  if (stream_id_ == kInvalidStreamId) {
    SPDY_BUG << "Expected nonzero stream id, saw: " << stream_id_;
    error_ = UNEXPECTED_STREAM_ID;
    return false;
  }
  total_bytes_received_ += headers_data_length;

  SpdyPinnableBufferPiece prefix, key, value;
  // Simultaneously tie lifetimes to the stack, and clear member variables.
  prefix.Swap(&headers_block_prefix_);
  key.Swap(&key_);

  // Apply the parsing state machine to the remaining prefix
  // from last invocation, plus newly-available headers data.
  Reader reader(prefix.buffer(), prefix.length(),
                headers_data, headers_data_length);
  while (error_ == NO_PARSER_ERROR) {
    ParserState next_state(FINISHED_HEADER);

    switch (state_) {
      case READING_HEADER_BLOCK_LEN:
        next_state = READING_KEY_LEN;
        ParseBlockLength(&reader);
        break;
      case READING_KEY_LEN:
        next_state = READING_KEY;
        ParseFieldLength(&reader);
        break;
      case READING_KEY:
        next_state = READING_VALUE_LEN;
        if (!reader.ReadN(next_field_length_, &key)) {
          error_ = NEED_MORE_DATA;
        }
        break;
      case READING_VALUE_LEN:
        next_state = READING_VALUE;
        ParseFieldLength(&reader);
        break;
      case READING_VALUE:
        next_state = FINISHED_HEADER;
        if (!reader.ReadN(next_field_length_, &value)) {
          error_ = NEED_MORE_DATA;
        } else {
          handler_->OnHeader(key, value);
        }
        break;
      case FINISHED_HEADER:
        // Prepare for next header or block.
        if (--remaining_key_value_pairs_for_frame_ > 0) {
          next_state = READING_KEY_LEN;
        } else {
          next_state = READING_HEADER_BLOCK_LEN;
          handler_->OnHeaderBlockEnd(total_bytes_received_);
          stream_id_ = kInvalidStreamId;
          // Expect to have consumed all buffer.
          if (reader.Available() != 0) {
            error_ = TOO_MUCH_DATA;
          }
        }
        break;
    }

    if (error_ == NO_PARSER_ERROR) {
      state_ = next_state;

      if (next_state == READING_HEADER_BLOCK_LEN) {
        // We completed reading a full header block. Return to caller.
        total_bytes_received_ = 0;
        break;
      }
    } else if (error_ == NEED_MORE_DATA) {
      // We can't continue parsing until more data is available. Make copies of
      // the key and buffer remainder, in preperation for the next invocation.
      if (state_ > READING_KEY) {
        key_.Swap(&key);
        key_.Pin();
      }
      reader.ReadN(reader.Available(), &headers_block_prefix_);
      headers_block_prefix_.Pin();
    }
  }
  return error_ == NO_PARSER_ERROR;
}

void SpdyHeadersBlockParser::ParseBlockLength(Reader* reader) {
  ParseLength(reader, &remaining_key_value_pairs_for_frame_);
  if (error_ == NO_PARSER_ERROR &&
      remaining_key_value_pairs_for_frame_ > max_headers_in_block_) {
    error_ = HEADER_BLOCK_TOO_LARGE;
  }
  if (error_ == NO_PARSER_ERROR) {
    handler_->OnHeaderBlockStart();
  }
}

void SpdyHeadersBlockParser::ParseFieldLength(Reader* reader) {
  ParseLength(reader, &next_field_length_);
  if (error_ == NO_PARSER_ERROR && next_field_length_ > kMaximumFieldLength) {
    error_ = HEADER_FIELD_TOO_LARGE;
  }
}

void SpdyHeadersBlockParser::ParseLength(Reader* reader,
                                         uint32_t* parsed_length) {
  char buffer[] = {0, 0, 0, 0};
  if (!reader->ReadN(kLengthFieldSize, buffer)) {
    error_ = NEED_MORE_DATA;
    return;
  }
  // Convert from network to host order and return the parsed out integer.
  *parsed_length =
      base::NetToHost32(*reinterpret_cast<const uint32_t*>(buffer));
}

size_t SpdyHeadersBlockParser::MaxNumberOfHeaders() {
  // Account for the length of the header block field.
  size_t max_bytes_for_headers = kMaximumFieldLength - kLengthFieldSize;

  // A minimal size header is twice the length field size (and has a
  // zero-lengthed key and a zero-lengthed value).
  return max_bytes_for_headers / (2 * kLengthFieldSize);
}

}  // namespace net
