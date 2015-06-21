// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack_string_util.h"

#include "base/basictypes.h"

namespace net {

bool StringPiecesEqualConstantTime(base::StringPiece str1,
                                   base::StringPiece str2) {
  size_t size = str1.size();
  if (str2.size() != size)
    return false;

  uint8 x = 0;
  for (size_t i = 0; i < size; ++i) {
    x |= str1[i] ^ str2[i];
  }
  return x == 0;
}

}  // namespace net
