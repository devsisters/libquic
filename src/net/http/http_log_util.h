// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_LOG_UTIL_
#define NET_HTTP_HTTP_LOG_UTIL_

#include <string>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/log/net_log.h"
#include "net/spdy/spdy_header_block.h"

namespace base {
class ListValue;
}  // namespace base

namespace net {

// Given an HTTP header |header| with value |value|, returns the elided version
// of the header value at |log_level|.
NET_EXPORT_PRIVATE std::string ElideHeaderValueForNetLog(
    NetLogCaptureMode capture_mode,
    const std::string& header,
    const std::string& value);

// Given an HTTP/2 GOAWAY frame |debug_data|, returns the elided version
// according to |capture_mode|.
NET_EXPORT_PRIVATE std::string ElideGoAwayDebugDataForNetLog(
    NetLogCaptureMode capture_mode,
    base::StringPiece debug_data);

// Given a SpdyHeaderBlock, return its base::ListValue representation.
std::unique_ptr<base::ListValue> ElideSpdyHeaderBlockForNetLog(
    const SpdyHeaderBlock& headers,
    NetLogCaptureMode capture_mode);

}  // namespace net

#endif  // NET_HTTP_HTTP_LOG_UTIL_
