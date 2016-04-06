// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/ip_address.h"

#include "base/strings/string_piece.h"
#include "base/strings/string_split.h"
#include "net/base/ip_address_number.h"
#include "net/base/parse_number.h"
#include "url/gurl.h"
#include "url/url_canon_ip.h"

namespace net {

IPAddress::IPAddress() {}

IPAddress::IPAddress(const IPAddressNumber& address) : ip_address_(address) {}

IPAddress::IPAddress(const IPAddress& other) = default;

IPAddress::IPAddress(const uint8_t* address, size_t address_len)
    : ip_address_(address, address + address_len) {}

IPAddress::IPAddress(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
  ip_address_.reserve(4);
  ip_address_.push_back(b0);
  ip_address_.push_back(b1);
  ip_address_.push_back(b2);
  ip_address_.push_back(b3);
}

IPAddress::IPAddress(uint8_t b0,
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
                     uint8_t b15) {
  const uint8_t address[] = {b0, b1, b2,  b3,  b4,  b5,  b6,  b7,
                             b8, b9, b10, b11, b12, b13, b14, b15};
  ip_address_ = std::vector<uint8_t>(std::begin(address), std::end(address));
}

IPAddress::~IPAddress() {}

bool IPAddress::IsIPv4() const {
  return ip_address_.size() == kIPv4AddressSize;
}

bool IPAddress::IsIPv6() const {
  return ip_address_.size() == kIPv6AddressSize;
}

bool IPAddress::IsValid() const {
  return IsIPv4() || IsIPv6();
}

bool IPAddress::IsReserved() const {
  return IsIPAddressReserved(ip_address_);
}

bool IPAddress::IsZero() const {
  for (auto x : ip_address_) {
    if (x != 0)
      return false;
  }

  return !empty();
}

bool IPAddress::IsIPv4MappedIPv6() const {
  return net::IsIPv4Mapped(ip_address_);
}

std::string IPAddress::ToString() const {
  return IPAddressToString(ip_address_);
}

bool IPAddress::AssignFromIPLiteral(const base::StringPiece& ip_literal) {
  std::vector<uint8_t> number;
  if (!ParseIPLiteralToNumber(ip_literal, &number))
    return false;

  std::swap(number, ip_address_);
  return true;
}

// static
IPAddress IPAddress::IPv4Localhost() {
  static const uint8_t kLocalhostIPv4[] = {127, 0, 0, 1};
  return IPAddress(kLocalhostIPv4);
}

// static
IPAddress IPAddress::IPv6Localhost() {
  static const uint8_t kLocalhostIPv6[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 1};
  return IPAddress(kLocalhostIPv6);
}

// static
IPAddress IPAddress::AllZeros(size_t num_zero_bytes) {
  return IPAddress(std::vector<uint8_t>(num_zero_bytes));
}

// static
IPAddress IPAddress::IPv4AllZeros() {
  return AllZeros(kIPv4AddressSize);
}

// static
IPAddress IPAddress::IPv6AllZeros() {
  return AllZeros(kIPv6AddressSize);
}

bool IPAddress::operator==(const IPAddress& that) const {
  return ip_address_ == that.ip_address_;
}

bool IPAddress::operator!=(const IPAddress& that) const {
  return ip_address_ != that.ip_address_;
}

bool IPAddress::operator<(const IPAddress& that) const {
  // Sort IPv4 before IPv6.
  if (ip_address_.size() != that.ip_address_.size()) {
    return ip_address_.size() < that.ip_address_.size();
  }

  return ip_address_ < that.ip_address_;
}

std::string IPAddressToStringWithPort(const IPAddress& address, uint16_t port) {
  return IPAddressToStringWithPort(address.bytes(), port);
}

std::string IPAddressToPackedString(const IPAddress& address) {
  return IPAddressToPackedString(address.bytes());
}

IPAddress ConvertIPv4ToIPv4MappedIPv6(const IPAddress& address) {
  return IPAddress(ConvertIPv4NumberToIPv6Number(address.bytes()));
}

IPAddress ConvertIPv4MappedIPv6ToIPv4(const IPAddress& address) {
  return IPAddress(ConvertIPv4MappedToIPv4(address.bytes()));
}

bool IPAddressMatchesPrefix(const IPAddress& ip_address,
                            const IPAddress& ip_prefix,
                            size_t prefix_length_in_bits) {
  return IPNumberMatchesPrefix(ip_address.bytes(), ip_prefix.bytes(),
                               prefix_length_in_bits);
}

bool ParseCIDRBlock(const std::string& cidr_literal,
                    IPAddress* ip_address,
                    size_t* prefix_length_in_bits) {
  // We expect CIDR notation to match one of these two templates:
  //   <IPv4-literal> "/" <number of bits>
  //   <IPv6-literal> "/" <number of bits>

  std::vector<base::StringPiece> parts = base::SplitStringPiece(
      cidr_literal, "/", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.size() != 2)
    return false;

  // Parse the IP address.
  if (!ip_address->AssignFromIPLiteral(parts[0]))
    return false;

  // Parse the prefix length.
  int number_of_bits = -1;
  if (!ParseNonNegativeDecimalInt(parts[1], &number_of_bits))
    return false;

  // Make sure the prefix length is in a valid range.
  if (number_of_bits < 0 ||
      number_of_bits > static_cast<int>(ip_address->size() * 8))
    return false;

  *prefix_length_in_bits = static_cast<size_t>(number_of_bits);
  return true;
}

bool ParseURLHostnameToAddress(const std::string& hostname,
                               IPAddress* ip_address) {
  if (hostname.size() >= 2 && hostname.front() == '[' &&
      hostname.back() == ']') {
    // Strip the square brackets that surround IPv6 literals.
    auto ip_literal =
        base::StringPiece(hostname).substr(1, hostname.size() - 2);
    return ip_address->AssignFromIPLiteral(ip_literal) && ip_address->IsIPv6();
  }

  return ip_address->AssignFromIPLiteral(hostname) && ip_address->IsIPv4();
}

unsigned CommonPrefixLength(const IPAddress& a1, const IPAddress& a2) {
  return CommonPrefixLength(a1.bytes(), a2.bytes());
}

unsigned MaskPrefixLength(const IPAddress& mask) {
  return MaskPrefixLength(mask.bytes());
}

}  // namespace net
