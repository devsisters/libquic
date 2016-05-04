// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_SPDY_UTILS_H_
#define NET_QUIC_SPDY_UTILS_H_

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <string>

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/quic/quic_header_list.h"
#include "net/quic/quic_protocol.h"
#include "net/spdy/spdy_framer.h"

namespace net {

class NET_EXPORT_PRIVATE SpdyUtils {
 public:
  static std::string SerializeUncompressedHeaders(
      const SpdyHeaderBlock& headers);

  // Parses |data| as a std::string containing serialized HTTP/2 HEADERS frame,
  // populating |headers| with the key->value std:pairs found.
  // |content_length| will be populated with the value of the content-length
  // header if one or more are present.
  // Returns true on success, false if parsing fails, or invalid keys are found.
  static bool ParseHeaders(const char* data,
                           uint32_t data_len,
                           int64_t* content_length,
                           SpdyHeaderBlock* headers);

  // Parses |data| as a std::string containing serialized HTTP/2 HEADERS frame,
  // populating |trailers| with the key->value std:pairs found.
  // The final offset header will be excluded from |trailers|, and instead the
  // value will be copied to |final_byte_offset|.
  // Returns true on success, false if parsing fails, or invalid keys are found.
  static bool ParseTrailers(const char* data,
                            uint32_t data_len,
                            size_t* final_byte_offset,
                            SpdyHeaderBlock* trailers);

  // Copies a list of headers to a SpdyHeaderBlock. Performs similar validation
  // to SpdyFramer::ParseHeaderBlockInBuffer and ParseHeaders, above.
  static bool CopyAndValidateHeaders(const QuicHeaderList& header_list,
                                     int64_t* content_length,
                                     SpdyHeaderBlock* headers);

  // Copies a list of headers to a SpdyHeaderBlock. Performs similar validation
  // to SpdyFramer::ParseHeaderBlockInBuffer and ParseTrailers, above.
  static bool CopyAndValidateTrailers(const QuicHeaderList& header_list,
                                      size_t* final_byte_offset,
                                      SpdyHeaderBlock* trailers);

  // Returns URL composed from scheme, authority, and path header
  // values, or empty string if any of those fields are missing.
  static std::string GetUrlFromHeaderBlock(const net::SpdyHeaderBlock& headers);

  // Returns hostname, or empty std::string if missing.
  static std::string GetHostNameFromHeaderBlock(const SpdyHeaderBlock& headers);

  // Returns true if result of |GetUrlFromHeaderBlock()| is non-empty
  // and is a well-formed URL.
  static bool UrlIsValid(const net::SpdyHeaderBlock& headers);

 private:
  DISALLOW_COPY_AND_ASSIGN(SpdyUtils);
};

}  // namespace net

#endif  // NET_QUIC_SPDY_UTILS_H_
