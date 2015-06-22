// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include "base/basictypes.h"
#include "net/base/int128.h"

const uint128_pod kuint128max = {
    static_cast<uint64>(0xFFFFFFFFFFFFFFFFULL),
    static_cast<uint64>(0xFFFFFFFFFFFFFFFFULL)
};

std::ostream& operator<<(std::ostream& o, const uint128& b) {
  return (o << b.hi_ << "::" << b.lo_);
}
