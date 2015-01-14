// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/cube_root.h"

#include "base/logging.h"

namespace {

// Find last bit in a 64-bit word.
int FindMostSignificantBit(uint64 x) {
  if (!x) {
    return 0;
  }
  int r = 0;
  if (x & 0xffffffff00000000ull) {
    x >>= 32;
    r += 32;
  }
  if (x & 0xffff0000u) {
    x >>= 16;
    r += 16;
  }
  if (x & 0xff00u) {
    x >>= 8;
    r += 8;
  }
  if (x & 0xf0u) {
    x >>= 4;
    r += 4;
  }
  if (x & 0xcu) {
    x >>= 2;
    r += 2;
  }
  if (x & 0x02u) {
    x >>= 1;
    r++;
  }
  if (x & 0x01u) {
    r++;
  }
  return r;
}

// 6 bits table [0..63]
const uint32 cube_root_table[] = {
    0,  54,  54,  54, 118, 118, 118, 118, 123, 129, 134, 138, 143, 147, 151,
  156, 157, 161, 164, 168, 170, 173, 176, 179, 181, 185, 187, 190, 192, 194,
  197, 199, 200, 202, 204, 206, 209, 211, 213, 215, 217, 219, 221, 222, 224,
  225, 227, 229, 231, 232, 234, 236, 237, 239, 240, 242, 244, 245, 246, 248,
  250, 251, 252, 254
};
}  // namespace

namespace net {

// Calculate the cube root using a table lookup followed by one Newton-Raphson
// iteration.
uint32 CubeRoot::Root(uint64 a) {
  uint32 msb = FindMostSignificantBit(a);
  DCHECK_LE(msb, 64u);

  if (msb < 7) {
    // MSB in our table.
    return ((cube_root_table[a]) + 31) >> 6;
  }
  // MSB          7,  8,  9, 10, 11, 12, 13, 14, 15, 16, ...
  // cubic_shift  1,  1,  1,  2,  2,  2,  3,  3,  3,  4, ...
  uint32 cubic_shift = (msb - 4);
  cubic_shift = ((cubic_shift * 342) >> 10);  // Div by 3, biased high.

  // 4 to 6 bits accuracy depending on MSB.
  uint64 root =
      ((cube_root_table[a >> (cubic_shift * 3)] + 10) << cubic_shift) >> 6;

  // Make one Newton-Raphson iteration.
  // Since x has an error (inaccuracy due to the use of fix point) we get a
  // more accurate result by doing x * (x - 1) instead of x * x.
  root = 2 * root + (a / (root * (root - 1)));
  root = ((root * 341) >> 10);  // Div by 3, biased low.
  return static_cast<uint32>(root);
}

}  // namespace net
