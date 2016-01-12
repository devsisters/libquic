// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_SIMPLE_BUFFER_ALLOCATOR_H_
#define NET_QUIC_SIMPLE_BUFFER_ALLOCATOR_H_

#include "net/quic/quic_protocol.h"

namespace net {

class NET_EXPORT_PRIVATE SimpleBufferAllocator : public QuicBufferAllocator {
 public:
  char* New(size_t size) override;
  void Delete(char* buffer) override;
};

}  // namespace net

#endif  // NET_QUIC_SIMPLE_BUFFER_ALLOCATOR_H_
