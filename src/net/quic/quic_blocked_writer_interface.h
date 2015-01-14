// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is an interface for all objects that want to be notified that
// the underlying UDP socket is available for writing (not write blocked
// anymore).

#ifndef NET_QUIC_QUIC_BLOCKED_WRITER_INTERFACE_H_
#define NET_QUIC_QUIC_BLOCKED_WRITER_INTERFACE_H_

#include "net/base/net_export.h"

namespace net {

class NET_EXPORT_PRIVATE QuicBlockedWriterInterface {
 public:
  virtual ~QuicBlockedWriterInterface() {}

  // Called by the PacketWriter when the underlying socket becomes writable
  // so that the BlockedWriter can go ahead and try writing.
  virtual void OnCanWrite() = 0;
};

}  // namespace net

#if defined(COMPILER_GCC)
namespace BASE_HASH_NAMESPACE {
// Hash pointers as if they were int's, but bring more entropy to the lower
// bits.
template <>
struct hash<net::QuicBlockedWriterInterface*> {
  std::size_t operator()(const net::QuicBlockedWriterInterface* ptr) const {
    size_t k = reinterpret_cast<size_t>(ptr);
    return k + (k >> 6);
  }
};
}
#endif

#endif  // NET_QUIC_QUIC_BLOCKED_WRITER_INTERFACE_H_
