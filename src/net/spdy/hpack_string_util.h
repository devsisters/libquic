// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_STRING_UTIL_H_
#define NET_SPDY_HPACK_STRING_UTIL_H_

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {

// All section references below are to
// http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-08

// A constant-time StringPiece comparison function.
bool NET_EXPORT_PRIVATE StringPiecesEqualConstantTime(
    base::StringPiece str1,
    base::StringPiece str2);

}  // namespace net

#endif  // NET_SPDY_HPACK_STRING_UTIL_H_
