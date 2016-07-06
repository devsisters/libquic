// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_DECODER_H_
#define NET_SPDY_HPACK_DECODER_H_

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/spdy/hpack/hpack_decoder_interface.h"
#include "net/spdy/hpack/hpack_header_table.h"
#include "net/spdy/hpack/hpack_input_stream.h"
#include "net/spdy/spdy_headers_handler_interface.h"
#include "net/spdy/spdy_protocol.h"

// An HpackDecoder decodes header sets as outlined in
// http://tools.ietf.org/html/rfc7541.

namespace net {

namespace test {
class HpackDecoderPeer;
}  // namespace test

class NET_EXPORT_PRIVATE HpackDecoder : public HpackDecoderInterface {
 public:
  friend class test::HpackDecoderPeer;

  HpackDecoder();
  ~HpackDecoder() override;

  // Called upon acknowledgement of SETTINGS_HEADER_TABLE_SIZE.
  void ApplyHeaderTableSizeSetting(size_t size_setting) override;

  // If a SpdyHeadersHandlerInterface is provided, HpackDecoder will emit
  // headers to it rather than accumulating them in a SpdyHeaderBlock.
  void HandleControlFrameHeadersStart(
      SpdyHeadersHandlerInterface* handler) override;

  // Called as headers data arrives. Returns false if an error occurred.
  // TODO(jgraettinger): A future version of this method will incrementally
  // parse and deliver headers via SpdyHeadersHandlerInterface. For now,
  // header data is buffered until HandleControlFrameHeadersComplete().
  bool HandleControlFrameHeadersData(const char* headers_data,
                                     size_t headers_data_length) override;

  // Called after a headers block has been completely delivered via
  // HandleControlFrameHeadersData(). Returns false if an error
  // occurred.  |compressed_len| if non-null will be set to the size
  // of the encoded buffered block that was accumulated in
  // HandleControlFrameHeadersData(), to support subsequent
  // calculation of compression percentage. Clears |handler_|.
  // TODO(jgraettinger): A
  // future version of this method will simply deliver the Cookie
  // header (which has been incrementally reconstructed) and notify
  // the visitor that the block is finished.
  bool HandleControlFrameHeadersComplete(size_t* compressed_len) override;

  // Accessor for the most recently decoded headers block. Valid until the next
  // call to HandleControlFrameHeadersData().
  // TODO(birenroy): Remove this method when all users of HpackDecoder specify
  // a SpdyHeadersHandlerInterface.
  const SpdyHeaderBlock& decoded_block() override;

  void SetHeaderTableDebugVisitor(
      std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor)
      override;

  void set_max_decode_buffer_size_bytes(
      size_t max_decode_buffer_size_bytes) override;

 private:
  // Adds the header representation to |decoded_block_|, applying the
  // following rules:
  //  - Multiple values of the Cookie header are joined, delmited by '; '.
  //    This reconstruction is required to properly handle Cookie crumbling
  //    (as per section 8.1.2.5 in RFC 7540).
  //  - Multiple values of other headers are joined and delimited by '\0'.
  //    Note that this may be too accomodating, as the sender's HTTP2 layer
  //    should have already joined and delimited these values.
  //
  // Returns false if a pseudo-header field follows a regular header one, which
  // MUST be treated as malformed, as per sections 8.1.2.3. of the HTTP2
  // specification (RFC 7540).
  //
  bool HandleHeaderRepresentation(base::StringPiece name,
                                  base::StringPiece value);

  HpackHeaderTable header_table_;

  // TODO(jgraettinger): Buffer for headers data, and storage for the last-
  // processed headers block. Both will be removed with the switch to
  // SpdyHeadersHandlerInterface.
  std::string headers_block_buffer_;
  SpdyHeaderBlock decoded_block_;

  // Scratch space for storing decoded literals.
  std::string key_buffer_, value_buffer_;

  // If non-NULL, handles decoded headers.
  SpdyHeadersHandlerInterface* handler_;
  size_t total_header_bytes_;

  // Flag to keep track of having seen the header block start.
  bool header_block_started_;

  // Total bytes have been removed from headers_block_buffer_.
  // Its value is updated during incremental decoding.
  uint32_t total_parsed_bytes_;

  // How much encoded data this decoder is willing to buffer.
  // Defaults to 256 KB.
  size_t max_decode_buffer_size_bytes_ = kMaxDecodeBufferSize;

  // Handlers for decoding HPACK opcodes and header representations
  // (or parts thereof). These methods return true on success and
  // false on error.
  bool DecodeNextOpcodeWrapper(HpackInputStream* input_stream);
  bool DecodeNextOpcode(HpackInputStream* input_stream);
  bool DecodeAtMostTwoHeaderTableSizeUpdates(HpackInputStream* input_stream);
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
