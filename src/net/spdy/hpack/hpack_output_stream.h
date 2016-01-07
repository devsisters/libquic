// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_OUTPUT_STREAM_H_
#define NET_SPDY_HPACK_OUTPUT_STREAM_H_

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/spdy/hpack/hpack_constants.h"

// All section references below are to
// http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-08

namespace net {

// An HpackOutputStream handles all the low-level details of encoding
// header fields.
class NET_EXPORT_PRIVATE HpackOutputStream {
 public:
  explicit HpackOutputStream();
  ~HpackOutputStream();

  // Appends the lower |bit_size| bits of |bits| to the internal buffer.
  //
  // |bit_size| must be > 0 and <= 8. |bits| must not have any bits
  // set other than the lower |bit_size| bits.
  void AppendBits(uint8_t bits, size_t bit_size);

  // Simply forwards to AppendBits(prefix.bits, prefix.bit-size).
  void AppendPrefix(HpackPrefix prefix);

  // Directly appends |buffer|.
  void AppendBytes(base::StringPiece buffer);

  // Appends the given integer using the representation described in
  // 6.1. If the internal buffer ends on a byte boundary, the prefix
  // length N is taken to be 8; otherwise, it is taken to be the
  // number of bits to the next byte boundary.
  //
  // It is guaranteed that the internal buffer will end on a byte
  // boundary after this function is called.
  void AppendUint32(uint32_t I);

  // Swaps the interal buffer with |output|.
  void TakeString(std::string* output);

 private:
  // The internal bit buffer.
  std::string buffer_;

  // If 0, the buffer ends on a byte boundary. If non-zero, the buffer
  // ends on the most significant nth bit. Guaranteed to be < 8.
  size_t bit_offset_;

  DISALLOW_COPY_AND_ASSIGN(HpackOutputStream);
};

}  // namespace net

#endif  // NET_SPDY_HPACK_OUTPUT_STREAM_H_
