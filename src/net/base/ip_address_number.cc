// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/ip_address_number.h"

#include <limits.h>

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "url/gurl.h"
#include "url/url_canon_ip.h"

namespace net {

namespace {

bool IPNumberPrefixCheck(const IPAddressNumber& ip_number,
                         const unsigned char* ip_prefix,
                         size_t prefix_length_in_bits) {
  // Compare all the bytes that fall entirely within the prefix.
  int num_entire_bytes_in_prefix = prefix_length_in_bits / 8;
  for (int i = 0; i < num_entire_bytes_in_prefix; ++i) {
    if (ip_number[i] != ip_prefix[i])
      return false;
  }

  // In case the prefix was not a multiple of 8, there will be 1 byte
  // which is only partially masked.
  int remaining_bits = prefix_length_in_bits % 8;
  if (remaining_bits != 0) {
    unsigned char mask = 0xFF << (8 - remaining_bits);
    int i = num_entire_bytes_in_prefix;
    if ((ip_number[i] & mask) != (ip_prefix[i] & mask))
      return false;
  }
  return true;
}

}  // namespace

// Don't compare IPv4 and IPv6 addresses (they have different range
// reservations). Keep separate reservation arrays for each IP type, and
// consolidate adjacent reserved ranges within a reservation array when
// possible.
// Sources for info:
// www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
// www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
// They're formatted here with the prefix as the last element. For example:
// 10.0.0.0/8 becomes 10,0,0,0,8 and fec0::/10 becomes 0xfe,0xc0,0,0,0...,10.
bool IsIPAddressReserved(const IPAddressNumber& host_addr) {
  static const unsigned char kReservedIPv4[][5] = {
      { 0,0,0,0,8 }, { 10,0,0,0,8 }, { 100,64,0,0,10 }, { 127,0,0,0,8 },
      { 169,254,0,0,16 }, { 172,16,0,0,12 }, { 192,0,2,0,24 },
      { 192,88,99,0,24 }, { 192,168,0,0,16 }, { 198,18,0,0,15 },
      { 198,51,100,0,24 }, { 203,0,113,0,24 }, { 224,0,0,0,3 }
  };
  static const unsigned char kReservedIPv6[][17] = {
      { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8 },
      { 0x40,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2 },
      { 0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2 },
      { 0xc0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3 },
      { 0xe0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4 },
      { 0xf0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5 },
      { 0xf8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6 },
      { 0xfc,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7 },
      { 0xfe,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,9 },
      { 0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10 },
      { 0xfe,0xc0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10 },
  };
  size_t array_size = 0;
  const unsigned char* array = NULL;
  switch (host_addr.size()) {
    case kIPv4AddressSize:
      array_size = arraysize(kReservedIPv4);
      array = kReservedIPv4[0];
      break;
    case kIPv6AddressSize:
      array_size = arraysize(kReservedIPv6);
      array = kReservedIPv6[0];
      break;
  }
  if (!array)
    return false;
  size_t width = host_addr.size() + 1;
  for (size_t i = 0; i < array_size; ++i, array += width) {
    if (IPNumberPrefixCheck(host_addr, array, array[width-1]))
      return true;
  }
  return false;
}

std::string IPAddressToString(const uint8_t* address, size_t address_len) {
  std::string str;
  url::StdStringCanonOutput output(&str);

  if (address_len == kIPv4AddressSize) {
    url::AppendIPv4Address(address, &output);
  } else if (address_len == kIPv6AddressSize) {
    url::AppendIPv6Address(address, &output);
  } else {
    CHECK(false) << "Invalid IP address with length: " << address_len;
  }

  output.Complete();
  return str;
}

std::string IPAddressToStringWithPort(const uint8_t* address,
                                      size_t address_len,
                                      uint16_t port) {
  std::string address_str = IPAddressToString(address, address_len);

  if (address_len == kIPv6AddressSize) {
    // Need to bracket IPv6 addresses since they contain colons.
    return base::StringPrintf("[%s]:%d", address_str.c_str(), port);
  }
  return base::StringPrintf("%s:%d", address_str.c_str(), port);
}

std::string IPAddressToString(const IPAddressNumber& addr) {
  return IPAddressToString(&addr.front(), addr.size());
}

std::string IPAddressToStringWithPort(const IPAddressNumber& addr,
                                      uint16_t port) {
  return IPAddressToStringWithPort(&addr.front(), addr.size(), port);
}

std::string IPAddressToPackedString(const IPAddressNumber& addr) {
  return std::string(reinterpret_cast<const char *>(&addr.front()),
                     addr.size());
}

bool ParseURLHostnameToNumber(const std::string& hostname,
                              IPAddressNumber* ip_number) {
  // |hostname| is an already canoncalized hostname, conforming to RFC 3986.
  // For an IP address, this is defined in Section 3.2.2 of RFC 3986, with
  // the canonical form for IPv6 addresses defined in Section 4 of RFC 5952.
  url::Component host_comp(0, hostname.size());

  // If it has a bracket, try parsing it as an IPv6 address.
  if (hostname[0] == '[') {
    ip_number->resize(16);  // 128 bits.
    return url::IPv6AddressToNumber(
        hostname.data(), host_comp, &(*ip_number)[0]);
  }

  // Otherwise, try IPv4.
  ip_number->resize(4);  // 32 bits.
  int num_components;
  url::CanonHostInfo::Family family = url::IPv4AddressToNumber(
      hostname.data(), host_comp, &(*ip_number)[0], &num_components);
  return family == url::CanonHostInfo::IPV4;
}

bool ParseIPLiteralToNumber(const base::StringPiece& ip_literal,
                            IPAddressNumber* ip_number) {
  // |ip_literal| could be either a IPv4 or an IPv6 literal. If it contains
  // a colon however, it must be an IPv6 address.
  if (ip_literal.find(':') != base::StringPiece::npos) {
    // GURL expects IPv6 hostnames to be surrounded with brackets.
    std::string host_brackets = "[";
    ip_literal.AppendToString(&host_brackets);
    host_brackets.push_back(']');
    url::Component host_comp(0, host_brackets.size());

    // Try parsing the hostname as an IPv6 literal.
    ip_number->resize(16);  // 128 bits.
    return url::IPv6AddressToNumber(host_brackets.data(), host_comp,
                                    &(*ip_number)[0]);
  }

  // Otherwise the string is an IPv4 address.
  ip_number->resize(4);  // 32 bits.
  url::Component host_comp(0, ip_literal.size());
  int num_components;
  url::CanonHostInfo::Family family = url::IPv4AddressToNumber(
      ip_literal.data(), host_comp, &(*ip_number)[0], &num_components);
  return family == url::CanonHostInfo::IPV4;
}

namespace {

const unsigned char kIPv4MappedPrefix[] =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
}

IPAddressNumber ConvertIPv4NumberToIPv6Number(
    const IPAddressNumber& ipv4_number) {
  DCHECK(ipv4_number.size() == 4);

  // IPv4-mapped addresses are formed by:
  // <80 bits of zeros>  + <16 bits of ones> + <32-bit IPv4 address>.
  IPAddressNumber ipv6_number;
  ipv6_number.reserve(16);
  ipv6_number.insert(ipv6_number.end(),
                     kIPv4MappedPrefix,
                     kIPv4MappedPrefix + arraysize(kIPv4MappedPrefix));
  ipv6_number.insert(ipv6_number.end(), ipv4_number.begin(), ipv4_number.end());
  return ipv6_number;
}

bool IsIPv4Mapped(const IPAddressNumber& address) {
  if (address.size() != kIPv6AddressSize)
    return false;
  return std::equal(address.begin(),
                    address.begin() + arraysize(kIPv4MappedPrefix),
                    kIPv4MappedPrefix);
}

IPAddressNumber ConvertIPv4MappedToIPv4(const IPAddressNumber& address) {
  DCHECK(IsIPv4Mapped(address));
  return IPAddressNumber(address.begin() + arraysize(kIPv4MappedPrefix),
                         address.end());
}

bool ParseCIDRBlock(const std::string& cidr_literal,
                    IPAddressNumber* ip_number,
                    size_t* prefix_length_in_bits) {
  // We expect CIDR notation to match one of these two templates:
  //   <IPv4-literal> "/" <number of bits>
  //   <IPv6-literal> "/" <number of bits>

  std::vector<base::StringPiece> parts = base::SplitStringPiece(
      cidr_literal, "/", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.size() != 2)
    return false;

  // Parse the IP address.
  if (!ParseIPLiteralToNumber(parts[0], ip_number))
    return false;

  // Parse the prefix length.
  int number_of_bits = -1;
  if (!base::StringToInt(parts[1], &number_of_bits))
    return false;

  // Make sure the prefix length is in a valid range.
  if (number_of_bits < 0 ||
      number_of_bits > static_cast<int>(ip_number->size() * 8))
    return false;

  *prefix_length_in_bits = static_cast<size_t>(number_of_bits);
  return true;
}

bool IPNumberMatchesPrefix(const IPAddressNumber& ip_number,
                           const IPAddressNumber& ip_prefix,
                           size_t prefix_length_in_bits) {
  // Both the input IP address and the prefix IP address should be
  // either IPv4 or IPv6.
  DCHECK(ip_number.size() == 4 || ip_number.size() == 16);
  DCHECK(ip_prefix.size() == 4 || ip_prefix.size() == 16);

  DCHECK_LE(prefix_length_in_bits, ip_prefix.size() * 8);

  // In case we have an IPv6 / IPv4 mismatch, convert the IPv4 addresses to
  // IPv6 addresses in order to do the comparison.
  if (ip_number.size() != ip_prefix.size()) {
    if (ip_number.size() == 4) {
      return IPNumberMatchesPrefix(ConvertIPv4NumberToIPv6Number(ip_number),
                                   ip_prefix, prefix_length_in_bits);
    }
    return IPNumberMatchesPrefix(ip_number,
                                 ConvertIPv4NumberToIPv6Number(ip_prefix),
                                 96 + prefix_length_in_bits);
  }

  return IPNumberPrefixCheck(ip_number, &ip_prefix[0], prefix_length_in_bits);
}

unsigned CommonPrefixLength(const IPAddressNumber& a1,
                            const IPAddressNumber& a2) {
  DCHECK_EQ(a1.size(), a2.size());
  for (size_t i = 0; i < a1.size(); ++i) {
    unsigned diff = a1[i] ^ a2[i];
    if (!diff)
      continue;
    for (unsigned j = 0; j < CHAR_BIT; ++j) {
      if (diff & (1 << (CHAR_BIT - 1)))
        return i * CHAR_BIT + j;
      diff <<= 1;
    }
    NOTREACHED();
  }
  return a1.size() * CHAR_BIT;
}

unsigned MaskPrefixLength(const IPAddressNumber& mask) {
  IPAddressNumber all_ones(mask.size(), 0xFF);
  return CommonPrefixLength(mask, all_ones);
}

}  // namespace net
