// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_HPACK_DECODER_INTERFACE_H_
#define NET_SPDY_HPACK_HPACK_DECODER_INTERFACE_H_

// HpackDecoderInterface is the base class for HPACK block decoders.
// HPACK is defined in http://tools.ietf.org/html/rfc7541

#include <stddef.h>

#include <memory>

#include "net/base/net_export.h"
#include "net/spdy/hpack/hpack_header_table.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_headers_handler_interface.h"

namespace net {

class NET_EXPORT_PRIVATE HpackDecoderInterface {
 public:
  virtual ~HpackDecoderInterface() {}

  // Called upon acknowledgement of SETTINGS_HEADER_TABLE_SIZE.
  virtual void ApplyHeaderTableSizeSetting(size_t size_setting) = 0;

  // If a SpdyHeadersHandlerInterface is provided, the decoder will emit
  // headers to it rather than accumulating them in a SpdyHeaderBlock.
  virtual void HandleControlFrameHeadersStart(
      SpdyHeadersHandlerInterface* handler) = 0;

  // Called as HPACK block fragments arrive. Returns false if an error occurred
  // while decoding the block.
  virtual bool HandleControlFrameHeadersData(const char* headers_data,
                                             size_t headers_data_length) = 0;

  // Called after a HPACK block has been completely delivered via
  // HandleControlFrameHeadersData(). Returns false if an error occurred.
  // |compressed_len| if non-null will be set to the size of the encoded
  // buffered block that was accumulated in HandleControlFrameHeadersData(),
  // to support subsequent calculation of compression percentage.
  // Discards the handler supplied at the start of decoding the block.
  // TODO(jamessynge): Determine if compressed_len is needed; it is used to
  // produce UUMA stat Net.SpdyHpackDecompressionPercentage, but only for
  // SPDY3, not HTTP2.
  virtual bool HandleControlFrameHeadersComplete(size_t* compressed_len) = 0;

  // Accessor for the most recently decoded headers block. Valid until the next
  // call to HandleControlFrameHeadersData().
  // TODO(birenroy): Remove this method when all users of HpackDecoder specify
  // a SpdyHeadersHandlerInterface.
  virtual const SpdyHeaderBlock& decoded_block() = 0;

  virtual void SetHeaderTableDebugVisitor(
      std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor) = 0;

  // How much encoded data this decoder is willing to buffer. Defaults to 32 KB.
  // See FLAGS_gfe2_reloadable_flag_remove_hpack_decode_buffer_size_limit, which
  // is increasing this to twice the decoded limit.
  virtual void set_max_decode_buffer_size_bytes(
      size_t max_decode_buffer_size_bytes) = 0;
};

}  // namespace net

#endif  // NET_SPDY_HPACK_HPACK_DECODER_INTERFACE_H_
