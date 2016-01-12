// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_simple_buffer_allocator.h"

namespace net {

char* SimpleBufferAllocator::New(size_t size) {
  return new char[size];
}

void SimpleBufferAllocator::Delete(char* buffer) {
  delete[] buffer;
}

}  // namespace net
