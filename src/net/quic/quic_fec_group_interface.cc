// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_fec_group_interface.h"

#include <limits>

#include "base/logging.h"
#include "base/stl_util.h"

namespace net {

void QuicFecGroupInterface::XorBuffers(const char* input,
                                       size_t size_in_bytes,
                                       char* output) {
#if defined(__i386__) || defined(__x86_64__)
  // On x86, alignment is not required and casting bytes to words is safe.

  // size_t is a reasonable approximation of how large a general-purpose
  // register is for the platforms and compilers Chrome is built on.
  typedef size_t platform_word;
  const size_t size_in_words = size_in_bytes / sizeof(platform_word);

  const platform_word* input_words =
      reinterpret_cast<const platform_word*>(input);
  platform_word* output_words = reinterpret_cast<platform_word*>(output);

  // Handle word-sized part of the buffer.
  size_t offset_in_words = 0;
  for (; offset_in_words < size_in_words; offset_in_words++) {
    output_words[offset_in_words] ^= input_words[offset_in_words];
  }

  // Handle the tail which does not fit into the word.
  for (size_t offset_in_bytes = offset_in_words * sizeof(platform_word);
       offset_in_bytes < size_in_bytes; offset_in_bytes++) {
    output[offset_in_bytes] ^= input[offset_in_bytes];
  }
#else
  // On ARM and most other plaforms, the code above could fail due to the
  // alignment errors.  Stick to byte-by-byte comparison.
  for (size_t offset = 0; offset < size_in_bytes; offset++) {
    output[offset] ^= input[offset];
  }
#endif /* defined(__i386__) || defined(__x86_64__) */
}

}  // namespace net
