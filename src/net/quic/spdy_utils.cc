// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/spdy_utils.h"

#include <memory>
#include <vector>

#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "net/spdy/spdy_frame_builder.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_protocol.h"
#include "url/gurl.h"

using base::StringPiece;
using std::string;
using std::vector;

namespace net {

// static
string SpdyUtils::SerializeUncompressedHeaders(const SpdyHeaderBlock& headers) {
  SpdyMajorVersion spdy_version = HTTP2;

  size_t length = SpdyFramer::GetSerializedLength(spdy_version, &headers);
  SpdyFrameBuilder builder(length, spdy_version);
  SpdyFramer framer(spdy_version);
  framer.SerializeHeaderBlockWithoutCompression(&builder, headers);
  SpdySerializedFrame block(builder.take());
  return string(block.data(), length);
}

// static
bool SpdyUtils::ParseHeaders(const char* data,
                             uint32_t data_len,
                             int64_t* content_length,
                             SpdyHeaderBlock* headers) {
  SpdyFramer framer(HTTP2);
  if (!framer.ParseHeaderBlockInBuffer(data, data_len, headers) ||
      headers->empty()) {
    return false;  // Headers were invalid.
  }

  if (ContainsKey(*headers, "content-length")) {
    // Check whether multiple values are consistent.
    base::StringPiece content_length_header = (*headers)["content-length"];
    vector<string> values =
        base::SplitString(content_length_header, base::StringPiece("\0", 1),
                          base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
    for (const string& value : values) {
      int new_value;
      if (!base::StringToInt(value, &new_value) || new_value < 0) {
        return false;
      }
      if (*content_length < 0) {
        *content_length = new_value;
        continue;
      }
      if (new_value != *content_length) {
        return false;
      }
    }
  }

  return true;
}

// static
bool SpdyUtils::ParseTrailers(const char* data,
                              uint32_t data_len,
                              size_t* final_byte_offset,
                              SpdyHeaderBlock* trailers) {
  SpdyFramer framer(HTTP2);
  if (!framer.ParseHeaderBlockInBuffer(data, data_len, trailers) ||
      trailers->empty()) {
    DVLOG(1) << "Request Trailers are invalid.";
    return false;  // Trailers were invalid.
  }

  // Pull out the final offset pseudo header which indicates the number of
  // response body bytes expected.
  auto it = trailers->find(kFinalOffsetHeaderKey);
  if (it == trailers->end() ||
      !base::StringToSizeT(it->second, final_byte_offset)) {
    DVLOG(1) << "Required key '" << kFinalOffsetHeaderKey << "' not present";
    return false;
  }
  // The final offset header is no longer needed.
  trailers->erase(it->first);

  // Trailers must not have empty keys, and must not contain pseudo headers.
  for (const auto& trailer : *trailers) {
    base::StringPiece key = trailer.first;
    base::StringPiece value = trailer.second;
    if (key.starts_with(":")) {
      DVLOG(1) << "Trailers must not contain pseudo-header: '" << key << "','"
               << value << "'.";
      return false;
    }

    // TODO(rjshade): Check for other forbidden keys, following the HTTP/2 spec.
  }

  DVLOG(1) << "Successfully parsed Trailers.";
  return true;
}

bool SpdyUtils::CopyAndValidateHeaders(const QuicHeaderList& header_list,
                                       int64_t* content_length,
                                       SpdyHeaderBlock* headers) {
  for (const auto& p : header_list) {
    const string& name = p.first;
    if (name.empty()) {
      DVLOG(1) << "Header name must not be empty.";
      return false;
    }

    if (std::any_of(name.begin(), name.end(), base::IsAsciiUpper<char>)) {
      DLOG(ERROR) << "Malformed header: Header name " << name
                  << " contains upper-case characters.";
      return false;
    }

    if (headers->find(name) != headers->end()) {
      DLOG(ERROR) << "Duplicate header '" << name << "' found.";
      return false;
    }

    (*headers)[name] = p.second;
  }

  if (ContainsKey(*headers, "content-length")) {
    // Check whether multiple values are consistent.
    StringPiece content_length_header = (*headers)["content-length"];
    vector<string> values =
        base::SplitString(content_length_header, base::StringPiece("\0", 1),
                          base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
    for (const string& value : values) {
      int new_value;
      if (!base::StringToInt(value, &new_value) || new_value < 0) {
        DLOG(ERROR) << "Content length was either unparseable or negative.";
        return false;
      }
      if (*content_length < 0) {
        *content_length = new_value;
        continue;
      }
      if (new_value != *content_length) {
        DLOG(ERROR) << "Parsed content length " << new_value << " is "
                    << "inconsistent with previously detected content length "
                    << *content_length;
        return false;
      }
    }
  }

  DVLOG(1) << "Successfully parsed headers: " << headers->DebugString();
  return true;
}

bool SpdyUtils::CopyAndValidateTrailers(const QuicHeaderList& header_list,
                                        size_t* final_byte_offset,
                                        SpdyHeaderBlock* trailers) {
  bool found_final_byte_offset = false;
  for (const auto& p : header_list) {
    const string& name = p.first;

    // Pull out the final offset pseudo header which indicates the number of
    // response body bytes expected.
    int offset;
    if (!found_final_byte_offset && name == kFinalOffsetHeaderKey &&
        base::StringToInt(p.second, &offset)) {
      *final_byte_offset = offset;
      found_final_byte_offset = true;
      continue;
    }

    if (name.empty() || name[0] == ':') {
      DVLOG(1) << "Trailers must not be empty, and must not contain pseudo-"
               << "headers. Found: '" << name << "'";
      return false;
    }

    if (std::any_of(name.begin(), name.end(), base::IsAsciiUpper<char>)) {
      DVLOG(1) << "Malformed header: Header name " << name
               << " contains upper-case characters.";
      return false;
    }

    if (trailers->find(name) != trailers->end()) {
      DVLOG(1) << "Duplicate header '" << name << "' found in trailers.";
      return false;
    }

    (*trailers)[name] = p.second;
  }

  if (!found_final_byte_offset) {
    DVLOG(1) << "Required key '" << kFinalOffsetHeaderKey << "' not present";
    return false;
  }

  // TODO(rjshade): Check for other forbidden keys, following the HTTP/2 spec.

  DVLOG(1) << "Successfully parsed Trailers: " << trailers->DebugString();
  return true;
}

// static
string SpdyUtils::GetUrlFromHeaderBlock(const SpdyHeaderBlock& headers) {
  SpdyHeaderBlock::const_iterator it = headers.find(":scheme");
  if (it == headers.end()) {
    return "";
  }
  std::string url = it->second.as_string();

  url.append("://");

  it = headers.find(":authority");
  if (it == headers.end()) {
    return "";
  }
  url.append(it->second.as_string());

  it = headers.find(":path");
  if (it == headers.end()) {
    return "";
  }
  url.append(it->second.as_string());
  return url;
}

// static
string SpdyUtils::GetHostNameFromHeaderBlock(const SpdyHeaderBlock& headers) {
  return GURL(GetUrlFromHeaderBlock(headers)).host();
}

// static
bool SpdyUtils::UrlIsValid(const SpdyHeaderBlock& headers) {
  string url(GetUrlFromHeaderBlock(headers));
  return url != "" && GURL(url).is_valid();
}

}  // namespace net
