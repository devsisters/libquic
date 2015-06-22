// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/ip_endpoint.h"

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/sys_byteorder.h"
#if defined(OS_WIN)
#include <winsock2.h>
#elif defined(OS_POSIX)
#include <netinet/in.h>
#endif
#include "net/base/net_util.h"

namespace net {

namespace {
// By definition, socklen_t is large enough to hold both sizes.
const socklen_t kSockaddrInSize = sizeof(struct sockaddr_in);
const socklen_t kSockaddrIn6Size = sizeof(struct sockaddr_in6);
}

IPEndPoint::IPEndPoint() : port_(0) {}

IPEndPoint::~IPEndPoint() {}

IPEndPoint::IPEndPoint(const IPAddressNumber& address, uint16_t port)
    : address_(address), port_(port) {
}

IPEndPoint::IPEndPoint(const IPEndPoint& endpoint) {
  address_ = endpoint.address_;
  port_ = endpoint.port_;
}

AddressFamily IPEndPoint::GetFamily() const {
  return GetAddressFamily(address_);
}

int IPEndPoint::GetSockAddrFamily() const {
  switch (address_.size()) {
    case kIPv4AddressSize:
      return AF_INET;
    case kIPv6AddressSize:
      return AF_INET6;
    default:
      NOTREACHED() << "Bad IP address";
      return AF_UNSPEC;
  }
}

bool IPEndPoint::ToSockAddr(struct sockaddr* address,
                            socklen_t* address_length) const {
  DCHECK(address);
  DCHECK(address_length);
  switch (address_.size()) {
    case kIPv4AddressSize: {
      if (*address_length < kSockaddrInSize)
        return false;
      *address_length = kSockaddrInSize;
      struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(address);
      memset(addr, 0, sizeof(struct sockaddr_in));
      addr->sin_family = AF_INET;
      addr->sin_port = base::HostToNet16(port_);
      memcpy(&addr->sin_addr, &address_[0], kIPv4AddressSize);
      break;
    }
    case kIPv6AddressSize: {
      if (*address_length < kSockaddrIn6Size)
        return false;
      *address_length = kSockaddrIn6Size;
      struct sockaddr_in6* addr6 =
          reinterpret_cast<struct sockaddr_in6*>(address);
      memset(addr6, 0, sizeof(struct sockaddr_in6));
      addr6->sin6_family = AF_INET6;
      addr6->sin6_port = base::HostToNet16(port_);
      memcpy(&addr6->sin6_addr, &address_[0], kIPv6AddressSize);
      break;
    }
    default:
      return false;
  }
  return true;
}

bool IPEndPoint::FromSockAddr(const struct sockaddr* sock_addr,
                              socklen_t sock_addr_len) {
  DCHECK(sock_addr);

  const uint8_t* address;
  size_t address_len;
  uint16_t port;
  if (!GetIPAddressFromSockAddr(sock_addr, sock_addr_len, &address,
                                &address_len, &port)) {
    return false;
  }

  address_.assign(address, address + address_len);
  port_ = port;
  return true;
}

std::string IPEndPoint::ToString() const {
  return IPAddressToStringWithPort(address_, port_);
}

std::string IPEndPoint::ToStringWithoutPort() const {
  return IPAddressToString(address_);
}

bool IPEndPoint::operator<(const IPEndPoint& that) const {
  // Sort IPv4 before IPv6.
  if (address_.size() != that.address_.size()) {
    return address_.size() < that.address_.size();
  }
  if (address_ != that.address_) {
    return address_ < that.address_;
  }
  return port_ < that.port_;
}

bool IPEndPoint::operator==(const IPEndPoint& that) const {
  return address_ == that.address_ && port_ == that.port_;
}

}  // namespace net
