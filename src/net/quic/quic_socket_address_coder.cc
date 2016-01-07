// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_socket_address_coder.h"

#include "net/base/sys_addrinfo.h"

using std::string;

namespace net {

namespace {

// For convenience, the values of these constants match the values of AF_INET
// and AF_INET6 on Linux.
const uint16_t kIPv4 = 2;
const uint16_t kIPv6 = 10;

}  // namespace

QuicSocketAddressCoder::QuicSocketAddressCoder() {}

QuicSocketAddressCoder::QuicSocketAddressCoder(const IPEndPoint& address)
    : address_(address) {}

QuicSocketAddressCoder::~QuicSocketAddressCoder() {}

string QuicSocketAddressCoder::Encode() const {
  string serialized;
  uint16_t address_family;
  switch (address_.GetSockAddrFamily()) {
    case AF_INET:
      address_family = kIPv4;
      break;
    case AF_INET6:
      address_family = kIPv6;
      break;
    default:
      return serialized;
  }
  serialized.append(reinterpret_cast<const char*>(&address_family),
                    sizeof(address_family));
  serialized.append(IPAddressToPackedString(address_.address()));
  uint16_t port = address_.port();
  serialized.append(reinterpret_cast<const char*>(&port), sizeof(port));
  return serialized;
}

bool QuicSocketAddressCoder::Decode(const char* data, size_t length) {
  uint16_t address_family;
  if (length < sizeof(address_family)) {
    return false;
  }
  memcpy(&address_family, data, sizeof(address_family));
  data += sizeof(address_family);
  length -= sizeof(address_family);

  size_t ip_length;
  switch (address_family) {
    case kIPv4:
      ip_length = kIPv4AddressSize;
      break;
    case kIPv6:
      ip_length = kIPv6AddressSize;
      break;
    default:
      return false;
  }
  if (length < ip_length) {
    return false;
  }
  IPAddressNumber ip(ip_length);
  memcpy(&ip[0], data, ip_length);
  data += ip_length;
  length -= ip_length;

  uint16_t port;
  if (length != sizeof(port)) {
    return false;
  }
  memcpy(&port, data, length);

  address_ = IPEndPoint(ip, port);
  return true;
}

}  // namespace net
