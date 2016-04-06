// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/parse_number.h"

#include "base/strings/string_number_conversions.h"

namespace net {

bool ParseNonNegativeDecimalInt(const base::StringPiece& input, int* output) {
  if (input.empty() || input[0] > '9' || input[0] < '0')
    return false;

  int result;
  if (!base::StringToInt(input, &result))
    return false;

  *output = result;
  return true;
}

}  // namespace net
