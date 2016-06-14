// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_HEADERS_BLOCK_PARSER_H_
#define NET_SPDY_SPDY_HEADERS_BLOCK_PARSER_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/spdy/spdy_headers_handler_interface.h"
#include "net/spdy/spdy_prefixed_buffer_reader.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

namespace test {

class SpdyHeadersBlockParserPeer;

}  // namespace test

// This class handles SPDY headers block bytes and parses out key-value pairs
// as they arrive. This class is not thread-safe, and assumes that all headers
// block bytes are processed in a single thread.
class NET_EXPORT_PRIVATE SpdyHeadersBlockParser {
 public:
  // Bound on acceptable header name or value length.
  static const size_t kMaximumFieldLength;  // = 16 * 1024

  // Constructor. The handler's OnHeader will be called for every key
  // value pair that we parsed from the headers block.
  SpdyHeadersBlockParser(SpdyMajorVersion spdy_version,
                         SpdyHeadersHandlerInterface* handler);

  virtual ~SpdyHeadersBlockParser();

  // Handles headers block data as it arrives. Returns false if an error has
  // been set, which can include the recoverable error NEED_MORE_DATA. Returns
  // true if the invocation completes the parse of the entire headers block,
  // in which case the parser is ready for a new headers block.
  bool HandleControlFrameHeadersData(SpdyStreamId stream_id,
                                     const char* headers_data,
                                     size_t len);
  enum ParserError {
    NO_PARSER_ERROR,
    // Set when parsing failed due to insufficient data.
    // This error is recoverable, by passing in new data.
    NEED_MORE_DATA,
    // Set when a complete block has been read, but unprocessed data remains.
    TOO_MUCH_DATA,
    // Set when a block exceeds |MaxNumberOfHeadersForVersion| headers.
    HEADER_BLOCK_TOO_LARGE,
    // Set when a header key or value exceeds |kMaximumFieldLength|.
    HEADER_FIELD_TOO_LARGE,
    // Set when the parser is given an unexpected stream ID.
    UNEXPECTED_STREAM_ID,
  };
  ParserError get_error() const { return error_; }

  SpdyMajorVersion spdy_version() const { return spdy_version_; }

  // Returns the maximal number of headers in a SPDY headers block.
  static size_t MaxNumberOfHeaders();

 private:
  typedef SpdyPrefixedBufferReader Reader;

  // Parses and sanity-checks header block length.
  void ParseBlockLength(Reader* reader);

  // Parses and sanity-checks header field length.
  void ParseFieldLength(Reader* reader);

  // Parses and decodes network-order lengths into |parsed_length|.
  void ParseLength(Reader* reader, uint32_t* parsed_length);

  // The state of the parser.
  enum ParserState {
    READING_HEADER_BLOCK_LEN,
    READING_KEY_LEN,
    READING_KEY,
    READING_VALUE_LEN,
    READING_VALUE,
    FINISHED_HEADER
  };
  ParserState state_;

  // The maximal number of headers in a SPDY headers block.
  const size_t max_headers_in_block_;

  // A running total of the bytes parsed since the last call to Reset().
  size_t total_bytes_received_;

  // Number of key-value pairs until we complete handling the current
  // headers block.
  uint32_t remaining_key_value_pairs_for_frame_;

  // The length of the next header field to be read (either key or value).
  uint32_t next_field_length_;

  // Handles key-value pairs as we parse them.
  SpdyHeadersHandlerInterface* handler_;

  // Holds unprocessed buffer remainders between calls to
  // |HandleControlFrameHeadersData|.
  SpdyPinnableBufferPiece headers_block_prefix_;

  // Holds the key of a partially processed header between calls to
  // |HandleControlFrameHeadersData|.
  SpdyPinnableBufferPiece key_;

  // The current header block stream identifier.
  SpdyStreamId stream_id_;

  ParserError error_;

  const SpdyMajorVersion spdy_version_;
};

}  // namespace net

#endif  // NET_SPDY_SPDY_HEADERS_BLOCK_PARSER_H_
