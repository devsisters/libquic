// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_IP_ADDRESS_NET_H_
#define NET_BASE_IP_ADDRESS_NET_H_

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "base/strings/string_piece.h"
#include "net/base/ip_address_number.h"
#include "net/base/net_export.h"

namespace net {

class NET_EXPORT IPAddress {
 public:
  static const size_t kIPv4AddressSize;
  static const size_t kIPv6AddressSize;

  // Creates a zero-sized, invalid address.
  IPAddress();

  // Creates an IP address from a deprecated IPAddressNumber.
  explicit IPAddress(const IPAddressNumber& address);

  // Copies the input address to |ip_address_|. The input is expected to be in
  // network byte order.
  template <size_t N>
  IPAddress(const uint8_t(&address)[N])
      : IPAddress(address, N) {}

  // Copies the input address to |ip_address_| taking an additional length
  // parameter. The input is expected to be in network byte order.
  IPAddress(const uint8_t* address, size_t address_len);

  ~IPAddress();

  // Returns true if the IP has |kIPv4AddressSize| elements.
  bool IsIPv4() const;

  // Returns true if the IP has |kIPv6AddressSize| elements.
  bool IsIPv6() const;

  // Returns true if the IP is either an IPv4 or IPv6 address. This function
  // only checks the address length.
  bool IsValid() const;

  // Returns true if an IP address hostname is in a range reserved by the IANA.
  // Works with both IPv4 and IPv6 addresses, and only compares against a given
  // protocols's reserved ranges.
  bool IsReserved() const;

  // Returns true if |ip_address_| is an IPv4-mapped IPv6 address.
  bool IsIPv4Mapped() const;

  // The size in bytes of |ip_address_|.
  size_t size() const { return ip_address_.size(); }

  // Returns true if the IP is an empty, zero-sized (invalid) address.
  bool empty() const { return ip_address_.empty(); }

  // Returns the canonical string representation of an IP address.
  // For example: "192.168.0.1" or "::1". The IP address must be
  // valid, calling this on an invalid address will result in a crash.
  std::string ToString() const;

  // Parses an IP address literal (either IPv4 or IPv6) to its numeric value.
  // Returns true on success and fills |ip_address| with the numeric value.
  static bool FromIPLiteral(const base::StringPiece& ip_literal,
                            IPAddress* ip_address) WARN_UNUSED_RESULT;

  // Returns the underlying byte vector.
  const std::vector<uint8_t>& bytes() const { return ip_address_; };

  bool operator==(const IPAddress& that) const;
  bool operator<(const IPAddress& that) const;

 private:
  // IPv4 addresses will have length kIPv4AddressSize, whereas IPv6 address
  // will have length kIPv6AddressSize.
  std::vector<uint8_t> ip_address_;

  // This class is copyable and assignable.
};

}  // namespace net

#endif  // NET_BASE_IP_ADDRESS_NET_H_
