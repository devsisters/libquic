// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_IP_ADDRESS_NUMBER_H_
#define NET_BASE_IP_ADDRESS_NUMBER_H_

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {

// IPAddressNumber is used to represent an IP address's numeric value as an
// array of bytes, from most significant to least significant. This is the
// network byte ordering.
//
// IPv4 addresses will have length 4, whereas IPv6 address will have length 16.
//
// TODO(Martijnc): Remove the IPAddressNumber typedef. New code should use
// IPAddress instead and existing code should be switched over.
// https://crbug.com/496258
typedef std::vector<unsigned char> IPAddressNumber;
typedef std::vector<IPAddressNumber> IPAddressList;

static const size_t kIPv4AddressSize = 4;
static const size_t kIPv6AddressSize = 16;

// Returns true if an IP address hostname is in a range reserved by the IANA.
// Works with both IPv4 and IPv6 addresses, and only compares against a given
// protocols's reserved ranges.
NET_EXPORT bool IsIPAddressReserved(const IPAddressNumber& address);

// Returns the string representation of an IP address.
// For example: "192.168.0.1" or "::1".
NET_EXPORT std::string IPAddressToString(const uint8_t* address,
                                         size_t address_len);

// Returns the string representation of an IP address along with its port.
// For example: "192.168.0.1:99" or "[::1]:80".
NET_EXPORT std::string IPAddressToStringWithPort(const uint8_t* address,
                                                 size_t address_len,
                                                 uint16_t port);

// Same as IPAddressToString() but for an IPAddressNumber.
NET_EXPORT std::string IPAddressToString(const IPAddressNumber& addr);

// Same as IPAddressToStringWithPort() but for an IPAddressNumber.
NET_EXPORT std::string IPAddressToStringWithPort(const IPAddressNumber& addr,
                                                 uint16_t port);

// Returns the address as a sequence of bytes in network-byte-order.
NET_EXPORT std::string IPAddressToPackedString(const IPAddressNumber& addr);

// Parses a URL-safe IP literal (see RFC 3986, Sec 3.2.2) to its numeric value.
// Returns true on success, and fills |ip_number| with the numeric value
NET_EXPORT bool ParseURLHostnameToNumber(const std::string& hostname,
                                         IPAddressNumber* ip_number);

// Parses an IP address literal (either IPv4 or IPv6) to its numeric value.
// Returns true on success and fills |ip_number| with the numeric value.
NET_EXPORT bool ParseIPLiteralToNumber(const base::StringPiece& ip_literal,
                                       IPAddressNumber* ip_number);

// Converts an IPv4 address to an IPv4-mapped IPv6 address.
// For example 192.168.0.1 would be converted to ::ffff:192.168.0.1.
NET_EXPORT_PRIVATE IPAddressNumber ConvertIPv4NumberToIPv6Number(
    const IPAddressNumber& ipv4_number);

// Returns true iff |address| is an IPv4-mapped IPv6 address.
NET_EXPORT_PRIVATE bool IsIPv4Mapped(const IPAddressNumber& address);

// Converts an IPv4-mapped IPv6 address to IPv4 address. Should only be called
// on IPv4-mapped IPv6 addresses.
NET_EXPORT_PRIVATE IPAddressNumber ConvertIPv4MappedToIPv4(
    const IPAddressNumber& address);

// Parses an IP block specifier from CIDR notation to an
// (IP address, prefix length) pair. Returns true on success and fills
// |*ip_number| with the numeric value of the IP address and sets
// |*prefix_length_in_bits| with the length of the prefix.
//
// CIDR notation literals can use either IPv4 or IPv6 literals. Some examples:
//
//    10.10.3.1/20
//    a:b:c::/46
//    ::1/128
NET_EXPORT bool ParseCIDRBlock(const std::string& cidr_literal,
                               IPAddressNumber* ip_number,
                               size_t* prefix_length_in_bits);

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
NET_EXPORT_PRIVATE bool IPNumberMatchesPrefix(const IPAddressNumber& ip_number,
                                              const IPAddressNumber& ip_prefix,
                                              size_t prefix_length_in_bits);

// Returns number of matching initial bits between the addresses |a1| and |a2|.
unsigned CommonPrefixLength(const IPAddressNumber& a1,
                            const IPAddressNumber& a2);

// Computes the number of leading 1-bits in |mask|.
unsigned MaskPrefixLength(const IPAddressNumber& mask);

}  // namespace net

#endif  // NET_BASE_IP_ADDRESS_NUMBER_H_
