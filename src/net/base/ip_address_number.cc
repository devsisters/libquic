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

std::string IPAddressToString(const uint8_t* address, size_t address_len) {
  std::string str;
  url::StdStringCanonOutput output(&str);

  if (address_len == kIPv4AddressSize) {
    url::AppendIPv4Address(address, &output);
  } else if (address_len == kIPv6AddressSize) {
    url::AppendIPv6Address(address, &output);
  }

  output.Complete();
  return str;
}

std::string IPAddressToStringWithPort(const uint8_t* address,
                                      size_t address_len,
                                      uint16_t port) {
  std::string address_str = IPAddressToString(address, address_len);
  if (address_str.empty())
    return address_str;

  if (address_len == kIPv6AddressSize) {
    // Need to bracket IPv6 addresses since they contain colons.
    return base::StringPrintf("[%s]:%d", address_str.c_str(), port);
  }
  return base::StringPrintf("%s:%d", address_str.c_str(), port);
}

std::string IPAddressToString(const IPAddressNumber& addr) {
  return IPAddressToString(addr.data(), addr.size());
}

std::string IPAddressToStringWithPort(const IPAddressNumber& addr,
                                      uint16_t port) {
  return IPAddressToStringWithPort(addr.data(), addr.size(), port);
}

std::string IPAddressToPackedString(const IPAddressNumber& addr) {
  return std::string(reinterpret_cast<const char*>(addr.data()), addr.size());
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
