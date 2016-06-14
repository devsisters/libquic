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
#include "net/base/net_export.h"

namespace net {

class NET_EXPORT IPAddress {
 public:
  enum : size_t { kIPv4AddressSize = 4, kIPv6AddressSize = 16 };

  // Creates a zero-sized, invalid address.
  IPAddress();

  // Copies the input address to |ip_address_|. The input is expected to be in
  // network byte order.
  explicit IPAddress(const std::vector<uint8_t>& address);

  IPAddress(const IPAddress& other);

  // Copies the input address to |ip_address_|. The input is expected to be in
  // network byte order.
  template <size_t N>
  IPAddress(const uint8_t(&address)[N])
      : IPAddress(address, N) {}

  // Copies the input address to |ip_address_| taking an additional length
  // parameter. The input is expected to be in network byte order.
  IPAddress(const uint8_t* address, size_t address_len);

  // Initializes |ip_address_| from the 4 bX bytes to form an IPv4 address.
  // The bytes are expected to be in network byte order.
  IPAddress(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3);

  // Initializes |ip_address_| from the 16 bX bytes to form an IPv6 address.
  // The bytes are expected to be in network byte order.
  IPAddress(uint8_t b0,
            uint8_t b1,
            uint8_t b2,
            uint8_t b3,
            uint8_t b4,
            uint8_t b5,
            uint8_t b6,
            uint8_t b7,
            uint8_t b8,
            uint8_t b9,
            uint8_t b10,
            uint8_t b11,
            uint8_t b12,
            uint8_t b13,
            uint8_t b14,
            uint8_t b15);

  ~IPAddress();

  // Returns true if the IP has |kIPv4AddressSize| elements.
  bool IsIPv4() const;

  // Returns true if the IP has |kIPv6AddressSize| elements.
  bool IsIPv6() const;

  // Returns true if the IP is either an IPv4 or IPv6 address. This function
  // only checks the address length.
  bool IsValid() const;

  // Returns true if the IP is in a range reserved by the IANA.
  // Works with both IPv4 and IPv6 addresses, and only compares against a given
  // protocols's reserved ranges.
  bool IsReserved() const;

  // Returns true if the IP is "zero" (e.g. the 0.0.0.0 IPv4 address).
  bool IsZero() const;

  // Returns true if |ip_address_| is an IPv4-mapped IPv6 address.
  bool IsIPv4MappedIPv6() const;

  // The size in bytes of |ip_address_|.
  size_t size() const { return ip_address_.size(); }

  // Returns true if the IP is an empty, zero-sized (invalid) address.
  bool empty() const { return ip_address_.empty(); }

  // Returns the canonical string representation of an IP address.
  // For example: "192.168.0.1" or "::1". Returns the empty string when
  // |ip_address_| is invalid.
  std::string ToString() const;

  // Parses an IP address literal (either IPv4 or IPv6) to its numeric value.
  // Returns true on success and fills |ip_address_| with the numeric value.
  bool AssignFromIPLiteral(const base::StringPiece& ip_literal)
      WARN_UNUSED_RESULT;

  // Returns the underlying byte vector.
  const std::vector<uint8_t>& bytes() const { return ip_address_; };

  // Returns an IPAddress instance representing the 127.0.0.1 address.
  static IPAddress IPv4Localhost();

  // Returns an IPAddress instance representing the ::1 address.
  static IPAddress IPv6Localhost();

  // Returns an IPAddress made up of |num_zero_bytes| zeros.
  static IPAddress AllZeros(size_t num_zero_bytes);

  // Returns an IPAddress instance representing the 0.0.0.0 address.
  static IPAddress IPv4AllZeros();

  // Returns an IPAddress instance representing the :: address.
  static IPAddress IPv6AllZeros();

  bool operator==(const IPAddress& that) const;
  bool operator!=(const IPAddress& that) const;
  bool operator<(const IPAddress& that) const;

 private:
  // IPv4 addresses will have length kIPv4AddressSize, whereas IPv6 address
  // will have length kIPv6AddressSize.
  std::vector<uint8_t> ip_address_;

  // This class is copyable and assignable.
};

using IPAddressList = std::vector<IPAddress>;

// Returns the canonical string representation of an IP address along with its
// port. For example: "192.168.0.1:99" or "[::1]:80".
NET_EXPORT std::string IPAddressToStringWithPort(const IPAddress& address,
                                                 uint16_t port);

// Returns the address as a sequence of bytes in network-byte-order.
NET_EXPORT std::string IPAddressToPackedString(const IPAddress& address);

// Converts an IPv4 address to an IPv4-mapped IPv6 address.
// For example 192.168.0.1 would be converted to ::ffff:192.168.0.1.
NET_EXPORT IPAddress ConvertIPv4ToIPv4MappedIPv6(const IPAddress& address);

// Converts an IPv4-mapped IPv6 address to IPv4 address. Should only be called
// on IPv4-mapped IPv6 addresses.
NET_EXPORT IPAddress ConvertIPv4MappedIPv6ToIPv4(const IPAddress& address);

// Compares an IP address to see if it falls within the specified IP block.
// Returns true if it does, false otherwise.
//
// The IP block is given by (|ip_prefix|, |prefix_length_in_bits|) -- any
// IP address whose |prefix_length_in_bits| most significant bits match
// |ip_prefix| will be matched.
//
// In cases when an IPv4 address is being compared to an IPv6 address prefix
// and vice versa, the IPv4 addresses will be converted to IPv4-mapped
// (IPv6) addresses.
NET_EXPORT bool IPAddressMatchesPrefix(const IPAddress& ip_address,
                                       const IPAddress& ip_prefix,
                                       size_t prefix_length_in_bits);

// Parses an IP block specifier from CIDR notation to an
// (IP address, prefix length) pair. Returns true on success and fills
// |*ip_address| with the numeric value of the IP address and sets
// |*prefix_length_in_bits| with the length of the prefix.
//
// CIDR notation literals can use either IPv4 or IPv6 literals. Some examples:
//
//    10.10.3.1/20
//    a:b:c::/46
//    ::1/128
NET_EXPORT bool ParseCIDRBlock(const std::string& cidr_literal,
                               IPAddress* ip_address,
                               size_t* prefix_length_in_bits);

// Parses a URL-safe IP literal (see RFC 3986, Sec 3.2.2) to its numeric value.
// Returns true on success, and fills |ip_address| with the numeric value.
// In other words, |hostname| must be an IPv4 literal, or an IPv6 literal
// surrounded by brackets as in [::1].
NET_EXPORT bool ParseURLHostnameToAddress(const base::StringPiece& hostname,
                                          IPAddress* ip_address)
    WARN_UNUSED_RESULT;

// Returns number of matching initial bits between the addresses |a1| and |a2|.
NET_EXPORT unsigned CommonPrefixLength(const IPAddress& a1,
                                       const IPAddress& a2);

// Computes the number of leading 1-bits in |mask|.
NET_EXPORT unsigned MaskPrefixLength(const IPAddress& mask);

// Checks whether |address| starts with |prefix|. This provides similar
// functionality as IPAddressMatchesPrefix() but doesn't perform automatic IPv4
// to IPv4MappedIPv6 conversions and only checks against full bytes.
template <size_t N>
bool IPAddressStartsWith(const IPAddress& address, const uint8_t (&prefix)[N]) {
  if (address.size() < N)
    return false;
  return std::equal(prefix, prefix + N, address.bytes().begin());
}

}  // namespace net

#endif  // NET_BASE_IP_ADDRESS_NET_H_
