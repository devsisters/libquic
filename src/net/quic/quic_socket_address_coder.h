// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_SOCKET_ADDRESS_CODER_H_
#define NET_QUIC_QUIC_SOCKET_ADDRESS_CODER_H_

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "base/macros.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_export.h"

namespace net {

// Serializes and parses a socket address (IP address and port), to be used in
// the kCADR tag in the ServerHello handshake message and the Public Reset
// packet.
class NET_EXPORT_PRIVATE QuicSocketAddressCoder {
 public:
  QuicSocketAddressCoder();
  explicit QuicSocketAddressCoder(const IPEndPoint& address);
  ~QuicSocketAddressCoder();

  std::string Encode() const;

  bool Decode(const char* data, size_t length);

  IPAddressNumber ip() const { return address_.address(); }

  uint16_t port() const { return address_.port(); }

 private:
  IPEndPoint address_;

  DISALLOW_COPY_AND_ASSIGN(QuicSocketAddressCoder);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_SOCKET_ADDRESS_CODER_H_
