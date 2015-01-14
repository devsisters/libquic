// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_DECODER_H_
#define NET_SPDY_HPACK_DECODER_H_

#include <map>
#include <string>
#include <vector>

#include "base/basictypes.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/spdy/hpack_header_table.h"
#include "net/spdy/hpack_input_stream.h"
#include "net/spdy/spdy_protocol.h"

// An HpackDecoder decodes header sets as outlined in
// http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-08

namespace net {

class HpackHuffmanTable;

namespace test {
class HpackDecoderPeer;
}  // namespace test

class NET_EXPORT_PRIVATE HpackDecoder {
 public:
  friend class test::HpackDecoderPeer;

  // |table| is an initialized HPACK Huffman table, having an
  // externally-managed lifetime which spans beyond HpackDecoder.
  explicit HpackDecoder(const HpackHuffmanTable& table);
  ~HpackDecoder();

  // Called upon acknowledgement of SETTINGS_HEADER_TABLE_SIZE.
  void ApplyHeaderTableSizeSetting(size_t size_setting) {
    header_table_.SetSettingsHeaderTableSize(size_setting);
  }

  // Called as headers data arrives. Returns false if an error occurred.
  // TODO(jgraettinger): A future version of this method will incrementally
  // parse and deliver headers via SpdyHeadersHandlerInterface. For now,
  // header data is buffered until HandleControlFrameHeadersComplete().
  bool HandleControlFrameHeadersData(SpdyStreamId stream_id,
                                     const char* headers_data,
                                     size_t headers_data_length);

  // Called after a headers block has been completely delivered via
  // HandleControlFrameHeadersData(). Returns false if an error occurred.
  // TODO(jgraettinger): A future version of this method will simply deliver
  // the Cookie header (which has been incrementally reconstructed) and notify
  // the visitor that the block is finished. For now, this method decodes the
  // complete buffered block, and stores results to |decoded_block_|.
  bool HandleControlFrameHeadersComplete(SpdyStreamId stream_id);

  // Accessor for the most recently decoded headers block. Valid until the next
  // call to HandleControlFrameHeadersData().
  // TODO(jgraettinger): This was added to facilitate re-encoding the block in
  // SPDY3 format for delivery to the SpdyFramer visitor, and will be removed
  // with the migration to SpdyHeadersHandlerInterface.
  const std::map<std::string, std::string>& decoded_block() {
    return decoded_block_;
  }

 private:
  // Adds the header representation to |decoded_block_|, applying the
  // following rules, as per sections 8.1.3.3 & 8.1.3.4 of the HTTP2 draft
  // specification:
  //  - Multiple values of the Cookie header are joined, delmited by '; '.
  //    This reconstruction is required to properly handle Cookie crumbling.
  //  - Multiple values of other headers are joined and delimited by '\0'.
  //    Note that this may be too accomodating, as the sender's HTTP2 layer
  //    should have already joined and delimited these values.
  //
  // Returns false if a pseudo-header field follows a regular header one, which
  // MUST be treated as malformed, as per sections 8.1.2.1. of the HTTP2 draft
  // specification.
  //
  // TODO(jgraettinger): This method will eventually emit to the
  // SpdyHeadersHandlerInterface visitor.
  bool HandleHeaderRepresentation(base::StringPiece name,
                                  base::StringPiece value);

  const uint32 max_string_literal_size_;
  HpackHeaderTable header_table_;

  // Incrementally reconstructed cookie value.
  std::string cookie_value_;

  // TODO(jgraettinger): Buffer for headers data, and storage for the last-
  // processed headers block. Both will be removed with the switch to
  // SpdyHeadersHandlerInterface.
  std::string headers_block_buffer_;
  std::map<std::string, std::string> decoded_block_;

  // Flag to keep track of having seen a regular header field.
  bool regular_header_seen_;

  // Huffman table to be applied to decoded Huffman literals,
  // and scratch space for storing those decoded literals.
  const HpackHuffmanTable& huffman_table_;
  std::string key_buffer_, value_buffer_;

  // Handlers for decoding HPACK opcodes and header representations
  // (or parts thereof). These methods return true on success and
  // false on error.
  bool DecodeNextOpcode(HpackInputStream* input_stream);
  bool DecodeNextHeaderTableSizeUpdate(HpackInputStream* input_stream);
  bool DecodeNextIndexedHeader(HpackInputStream* input_stream);
  bool DecodeNextLiteralHeader(HpackInputStream* input_stream,
                               bool should_index);
  bool DecodeNextName(HpackInputStream* input_stream,
                      base::StringPiece* next_name);
  bool DecodeNextStringLiteral(HpackInputStream* input_stream,
                               bool is_header_key,  // As distinct from a value.
                               base::StringPiece* output);

  DISALLOW_COPY_AND_ASSIGN(HpackDecoder);
};

}  // namespace net

#endif  // NET_SPDY_HPACK_DECODER_H_
